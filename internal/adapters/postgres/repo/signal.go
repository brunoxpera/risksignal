package repo

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/brunoxpera/risksignal/internal/adapters/postgres/gen"
	"github.com/brunoxpera/risksignal/internal/application"
	"github.com/brunoxpera/risksignal/internal/domain"
)

// SignalRepo is the postgres implementation of application.SignalRepo
// (risk_signals.sql: insert + the joined working-list reads of ARCH-001 §4).
type SignalRepo struct {
	q *gen.Queries
}

// NewSignalRepo binds the repository to one query set (pool-scoped for the
// reads; write methods rebind per transaction).
func NewSignalRepo(q *gen.Queries) *SignalRepo { return &SignalRepo{q: q} }

// compile-time check that the repository satisfies its port.
var _ application.SignalRepo = (*SignalRepo)(nil)

// Create implements application.SignalRepo. The id, status ('new') and
// version (1) come from the database default and the column defaults; the
// stored row is mapped back into the domain aggregate.
func (r *SignalRepo) Create(ctx context.Context, tx application.Tx, rec application.SignalRecord, createdAt time.Time) (domain.RiskSignal, error) {
	const op = "create_signal"

	matchID, err := toUUID(rec.MatchID)
	if err != nil {
		return domain.RiskSignal{}, application.ValidationError(op, err)
	}
	factors, err := json.Marshal(rec.Factors)
	if err != nil {
		return domain.RiskSignal{}, application.InfraError(op, err)
	}
	row, err := r.q.WithTx(tx).InsertRiskSignal(ctx, gen.InsertRiskSignalParams{
		MatchID:     matchID,
		Priority:    string(rec.Priority),
		Owner:       pgtype.Text{},
		DueAt:       pgtype.Timestamptz{},
		ClosedAt:    pgtype.Timestamptz{},
		RuleVersion: rec.RuleVersion,
		Factors:     factors,
		CreatedAt:   toTS(createdAt),
	})
	if err != nil {
		return domain.RiskSignal{}, mapDBError(op, err)
	}
	return riskSignalFromRow(row)
}

// GetByID implements application.SignalRepo with the joined detail view.
func (r *SignalRepo) GetByID(ctx context.Context, id string) (application.Signal, error) {
	const op = "get_signal"

	uid, err := toUUID(id)
	if err != nil {
		return application.Signal{}, application.ValidationError(op, err)
	}
	row, err := r.q.GetSignalByID(ctx, uid)
	if err != nil {
		return application.Signal{}, mapDBError(op, err) // pgx.ErrNoRows → not-found
	}
	return toSignalView(signalJoin(row)), nil
}

// List implements application.SignalRepo. The SQL orders by priority
// (P1→P4), created_at and id and limits the result; the offset window is
// fetched in one pass (max_rows = offset+limit+1, rows skipped client-side)
// so a page boundary is exact without a second query. A keyset push-down can
// replace this later without touching the port.
func (r *SignalRepo) List(ctx context.Context, filter application.SignalFilter, limit, offset int) ([]application.Signal, error) {
	const op = "list_signals"

	if offset < 0 {
		return nil, application.Validationf(op, "negative offset")
	}
	// The window is computed in int64 so the addition itself cannot
	// overflow, then checked against the int32 max_rows column: an
	// overflowing window (negative limit or an offset near MaxInt) is a
	// validation error, never a silent truncation.
	maxRows := int64(offset) + int64(limit) + 1
	if maxRows <= 0 || maxRows > math.MaxInt32 {
		return nil, application.Validationf(op, "page window offset+limit+1 = %d outside [1,%d]", maxRows, math.MaxInt32)
	}
	rows, err := r.q.ListSignals(ctx, gen.ListSignalsParams{
		Priority: toTextOptPtr(filter.Priority),
		Status:   toTextOptPtr(filter.Status),
		MaxRows:  int32(maxRows),
	})
	if err != nil {
		return nil, mapDBError(op, err)
	}
	if offset >= len(rows) {
		return []application.Signal{}, nil
	}
	rows = rows[offset:]
	out := make([]application.Signal, 0, len(rows))
	for _, row := range rows {
		out = append(out, toSignalView(signalJoin(row)))
	}
	return out, nil
}

// ExistsByMatchID implements application.SignalRepo (ARCH-001 §3 step 5).
func (r *SignalRepo) ExistsByMatchID(ctx context.Context, matchID string) (bool, error) {
	const op = "exists_signal_by_match"

	uid, err := toUUID(matchID)
	if err != nil {
		return false, application.ValidationError(op, err)
	}
	if _, err := r.q.GetSignalByMatchID(ctx, uid); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, mapDBError(op, err)
	}
	return true, nil
}

// toTextOptPtr maps an optional domain enum onto the nullable filter column.
func toTextOptPtr[T ~string](v *T) pgtype.Text {
	if v == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: string(*v), Valid: true}
}

// signalJoin is the shared shape of the two generated joined row types
// (GetSignalByIDRow and ListSignalsRow are structurally identical); the
// conversion keeps the per-column mapping in one place.
type signalJoin struct {
	ID               pgtype.UUID
	MatchID          pgtype.UUID
	Priority         string
	Status           string
	Owner            pgtype.Text
	DueAt            pgtype.Timestamptz
	ClosedAt         pgtype.Timestamptz
	Version          int32
	RuleVersion      string
	Factors          []byte
	CreatedAt        pgtype.Timestamptz
	CveID            string
	Summary          string
	Method           string
	Confidence       string
	Vendor           string
	Product          string
	ComponentVersion string
	AssetID          pgtype.UUID
	AssetExternalID  string
	AssetType        string
	AssetName        string
	AssetEnvironment string
	AssetCriticality string
	AssetExposure    string
}

// toSignalView maps one joined row onto the application view.
func toSignalView(j signalJoin) application.Signal {
	s := application.Signal{
		ID:         uuidString(j.ID),
		MatchID:    uuidString(j.MatchID),
		CveID:      j.CveID,
		Priority:   domain.Priority(j.Priority),
		Status:     domain.SignalStatus(j.Status),
		Confidence: domain.Confidence(j.Confidence),
		Method:     domain.MatchMethod(j.Method),
		Asset: application.SignalAsset{
			ID:          uuidString(j.AssetID),
			Name:        j.AssetName,
			Type:        domain.AssetType(j.AssetType),
			Criticality: domain.Criticality(j.AssetCriticality),
			Exposure:    domain.Exposure(j.AssetExposure),
		},
		Product: application.SignalProduct{
			Vendor:  j.Vendor,
			Product: j.Product,
			Version: j.ComponentVersion,
		},
		Summary:   j.Summary,
		CreatedAt: j.CreatedAt.Time,
		Version:   int(j.Version),
	}
	if j.DueAt.Valid {
		t := j.DueAt.Time
		s.DueAt = &t
	}
	return s
}

// riskSignalFromRow maps a stored risk_signals row back into the domain
// aggregate (the persistence-layer mapping the domain package sanctions).
func riskSignalFromRow(row gen.RiskSignal) (domain.RiskSignal, error) {
	var factors domain.PriorityFactors
	if err := json.Unmarshal(row.Factors, &factors); err != nil {
		return domain.RiskSignal{}, application.InfraError("create_signal", err)
	}
	return domain.RiskSignal{
		ID:          uuidString(row.ID),
		MatchID:     uuidString(row.MatchID),
		Priority:    domain.Priority(row.Priority),
		Status:      domain.SignalStatus(row.Status),
		Version:     int(row.Version),
		RuleVersion: row.RuleVersion,
		Factors:     factors,
	}, nil
}
