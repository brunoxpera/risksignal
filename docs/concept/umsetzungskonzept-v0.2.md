# UMSETZUNGSKONZEPT RiskSignal

**Technische Realisierung des Fachkonzepts v0.2**

| Merkmal | Angabe |
|---|---|
| Dokumentstatus | Entwurf - Grundlage für Detailplanung, Umsetzung und technische Abnahme |
| Version | 0.2 |
| Datum | 8. September 2026 |
| Bezugsdokument | RiskSignal Fachkonzept v0.2 |
| Projektphase | Konzeption; Produkt befindet sich in Entwicklung |
| Verantwortlich | Bruno Schriber / xpera GmbH |

> **Transparenzhinweis:** Dieses Dokument beschreibt die geplante technische Umsetzung. Architektur, Schnittstellen und Abnahmekriterien sind Soll-Vorgaben. Funktionen gelten erst nach Implementierung, erfolgreicher Prüfung und dokumentierter Abnahme als realisiert.

## Dokumentzweck

Das Umsetzungskonzept übersetzt die fachlichen Anforderungen von RiskSignal in eine belastbare technische Lösung. Es legt Architektur, Komponenten, Datenhaltung, Integrationen, Sicherheitsmechanismen, Betriebsfähigkeit, Qualitätssicherung und Umsetzungsreihenfolge so weit fest, dass daraus Arbeitspakete, technische Aufgaben und Abnahmetests abgeleitet werden können.

## Inhaltsübersicht

1. Grundlagen und Architekturentscheide
2. Systemkontext und Zielarchitektur
3. Technologie- und Strukturvorgaben
4. Laufzeit- und Bereitstellungsarchitektur
5. Anwendungskomponenten
6. Domänen- und Datenmodell
7. Datenbank- und Persistenzkonzept
8. Quellenintegration und Verarbeitung
9. Matching, Priorisierung und SLA
10. API-Konzept
11. Browseroberfläche und CLI
12. Identität, Berechtigungen und Sicherheit
13. Audit, Aufbewahrung und Datenschutz
14. Hintergrundverarbeitung und Benachrichtigungen
15. Ticketing-Vorbereitung
16. Observability und Betrieb
17. Test-, Qualitäts- und Lieferkonzept
18. Umsetzungsplan und Lieferobjekte
19. Technische Abnahme und Rückverfolgbarkeit
20. Risiken, Annahmen und offene Detailentscheide
21. Referenzen

---

## 1. Grundlagen und Architekturentscheide

Das Umsetzungskonzept basiert auf dem Fachkonzept v0.2. Die fachlichen Anforderungen FR-001 bis FR-034 und NFR-001 bis NFR-015 bleiben führend. Technische Entscheidungen dürfen diese Vorgaben präzisieren, aber nicht abschwächen. Bei Widersprüchen hat das Fachkonzept Vorrang, bis eine dokumentierte Änderung beschlossen wurde.

### 1.1 Leitprinzipien

- Modularer Monolith statt vorzeitiger Microservice-Aufteilung: klare Modulgrenzen bei einfacher lokaler und privater Bereitstellung.
- API-first: alle fachlichen Kernfunktionen sind über eine versionierte HTTP-API verfügbar.
- Ports und Adapter: externe Quellen, Identitätsanbieter, Benachrichtigungen und spätere Ticketing-Systeme bleiben austauschbar.
- Deterministische Fachlogik: Matching, Priorisierung, Status und Reaktionsfristen sind reproduzierbar und testbar.
- Nachvollziehbarkeit vor Automatisierung: Evidenz, Regelversion und menschliche Entscheidungen bleiben sichtbar.
- Sichere Standardeinstellungen: Online-Betrieb ohne lokalen Authentisierungs-Bypass, minimale Berechtigungen und keine Geheimnisse im Quellcode.
- Wiederholbare Bereitstellung: lokale Demo und private Online-Demo entstehen aus denselben versionierten Artefakten.

### 1.2 Verbindliche technische Entscheide

| ID | Entscheid | Begründung |
|---|---|---|
| ADR-001 | Go-basierter modularer Monolith mit mehreren Prozessmodi aus einem Repository. | Hohe fachliche Kohärenz, geringer Betriebsaufwand und dennoch klare Erweiterungspunkte. |
| ADR-002 | PostgreSQL als alleinige operative Datenbank des MVP. | Transaktionen, Constraints, relationale Nachweise und flexible JSON-Rohdaten ohne zusätzlichen Datenspeicher. |
| ADR-003 | REST/JSON mit OpenAPI 3.1 als externer API-Vertrag. | Breite Interoperabilität, testbarer Vertrag und einfache CLI-/Integrationsnutzung. |
| ADR-004 | Serverseitig gerenderte Weboberfläche mit gezielter progressiver Interaktion. | Go bleibt sichtbar im Gesamtprojekt; weniger Frontend-Komplexität für den MVP. |
| ADR-005 | Persistente Job-Queue und Outbox in PostgreSQL. | Idempotente Hintergrundverarbeitung ohne zusätzlichen Broker im MVP. |
| ADR-006 | OIDC für Benutzer und standardisierte Bearer Tokens für API/Automation. | Keine eigene Passwortverwaltung und saubere Trennung von Identität und Berechtigung. |
| ADR-007 | Containerisierte Bereitstellung; lokal via Compose, private Demo auf einem gehärteten Einzelhost. | Reproduzierbar, wirtschaftlich und passend zur vereinbarten Demo-Stufe. |
| ADR-008 | Routing auf net/http ServeMux, kein Framework; Toolchain auf Go 1.27 fixiert. | Standardbibliothek deckt die Endpunktliste ab; keine zentrale Framework-Abhängigkeit. |
| ADR-009 | Datenzugriff über sqlc-generierte Abfragen auf pgx/v5, ohne database/sql. | SQL bleibt sichtbar und prüfbar; Drift wird zum Buildfehler. |
| ADR-010 | Migrationen mit goose, eingebettet; plus ein eigenes Prüfsummen-Log. | Rückwirkend veränderte, bereits angewendete Migrationen werden erkannt. |
| ADR-011 | Generierte Server-Interfaces aus OpenAPI sind verbindlich (oapi-codegen v2). | Vertragsdrift wird zum Kompilierfehler statt zu einem Testbefund. |
| ADR-012 | Massen-Matching läuft inventargetrieben; Kandidaten-Vorfilter vor Job-Erzeugung. | Neue Jobtypen matching.rebuild und Batch-Payload für matching.recompute. |
| ADR-013 | Bei Bulk-Dateiquellen ist ein Rohdatensatz die Datei; Vollbestände über TRUNCATE + COPY. | epss_current ohne Fremdschlüssel; epss_history nur mit Inventarbezug. |
| ADR-014 | Benutzer werden deaktiviert, nie gelöscht; reversible Pseudonymisierung mit kontrollierter Auflösung. | Auflösung berechtigungsgesteuert und selbst-auditiert (audit.reveal_identity). |
| ADR-015 | Matching ist methodengeführt; der Score ist abgeleitet. | method ist autoritativ; drei fehlende Regeltabellen werden ergänzt. |

### 1.3 Bewusst nicht gewählte Ansätze

- Keine Microservices im MVP: unabhängige Skalierung und getrennte Teams rechtfertigen die zusätzliche Komplexität noch nicht.
- Kein Kafka, RabbitMQ oder Redis als Pflichtkomponente: Jobs und Integrationsereignisse werden zunächst transaktional in PostgreSQL geführt.
- Keine KI-basierte Klassifikation: Priorisierung und Matching bleiben erklärbar und deterministisch.
- Kein Single-Page-Application-Framework als Voraussetzung: die Weboberfläche konzentriert sich auf Triage und Administration.
- Keine produktionsreife Hochverfügbarkeit oder Mehrmandantenfähigkeit im MVP.

---

## 2. Systemkontext und Zielarchitektur

RiskSignal wird als eigenständige Anwendung betrieben. Die Plattform liest ausschliesslich freigegebene öffentliche Quellen und autorisierte Inventardaten. Sie greift nicht aktiv auf die inventarisierten Zielsysteme zu. Benutzer und Automationen bedienen dieselbe Fachlogik über unterschiedliche Adapter.

### 2.1 Systemgrenzen

| Bereich | Innerhalb RiskSignal | Ausserhalb RiskSignal |
|---|---|---|
| Identität | Zuordnung externer Identitäten zu internen Rollen und Berechtigungen. | Passwortverwaltung, MFA-Verfahren und Benutzerlebenszyklus des Identity Providers. |
| Security-Daten | Abruf, Validierung, Normalisierung, Versionierung und Evidenzbildung. | Erstellung und fachliche Verantwortung der öffentlichen Quelldaten. |
| Inventar | Import, Datenqualität, Komponentenmodell, Matching und fachliche Korrekturen. | Discovery, Scanning oder automatische Erfassung produktiver Systeme. |
| Bearbeitung | Priorisierung, Triage, SLA, Status, Zuweisung, Kommentar und Audit. | Patch-Ausführung und operative Änderung an Zielsystemen. |
| Integrationen | Versionierte API, Benachrichtigungs- und Ticketing-Ports. | Konkreter produktiver Ticketing-Adapter im MVP. |

### 2.2 Logische Architektur

```mermaid
flowchart TB
    subgraph Kanaele["Kanäle"]
        Browser
        CLI
        APIClients["API-Clients"]
    end
    subgraph Adapter
        WebAdapter["Web-Adapter"]
        RESTAPI["REST-API"]
        CLIAdapter["CLI-Adapter"]
        WorkerScheduler["Worker / Scheduler"]
    end
    subgraph AnwendungDomaene["Anwendung / Domäne"]
        Inventar
        Quellen
        MatchingPrio["Matching & Priorität"]
        SignalSlaAudit["Signal, SLA & Audit"]
    end
    subgraph Infrastruktur
        PostgreSQL
        OIDC
        NVDKEVEPSS["NVD / KEV / EPSS"]
        MailWebhookTicket["Mail / Webhook / Ticket-Port"]
    end
    Kanaele --> Adapter --> AnwendungDomaene --> Infrastruktur
```

*Abbildung 1: Alle Bedienkanäle nutzen gemeinsame Anwendungsdienste und Domänenregeln. Externe Systeme werden ausschliesslich über Adapter angebunden.*

### 2.3 Verantwortungsgrenzen der Schichten

- Kanäle präsentieren Daten oder starten Anwendungsfälle. Sie enthalten keine Priorisierungs-, Matching- oder Statuslogik.
- Adapter übersetzen HTTP, CLI, OIDC, Datenbank- und Quellprotokolle in interne Ports.
- Anwendungsdienste koordinieren Transaktionen, Berechtigungen, Domänenobjekte und Ereignisse.
- Die Domäne enthält Regeln und Zustandsübergänge ohne Abhängigkeit von HTTP, Datenbank oder Benutzeroberfläche.
- Infrastrukturadapter realisieren Persistenz und Kommunikation. Ihr Ausfall darf fachliche Konsistenz nicht verletzen.

---

## 3. Technologie- und Strukturvorgaben

Versionen werden in Build und Lock-Dateien fixiert. Das Projekt verwendet bei Umsetzungsstart Go 1.27, identisch gehalten in go.mod, Containerfile und CI. Abhängigkeiten werden bewusst begrenzt und müssen Lizenz-, Wartungs- und Sicherheitsprüfungen bestehen.

### 3.1 Technologiestack

| Bereich | Vorgabe | Einsatz |
|---|---|---|
| Programmiersprache | Go, ein Repository und ein Go-Modul. | API, Web, CLI, Worker, Scheduler und Fachlogik. |
| HTTP | Go net/http mit ServeMux; Middleware-Verkettung im Repository. | REST-Endpunkte, Middleware, Health und serverseitige Webrouten. |
| API-Vertrag | OpenAPI 3.1, schema-first. | Dokumentation, Contract-Tests und verbindlich generierte Server-Interfaces und Typen; Client-Generierung optional. |
| Persistenz | PostgreSQL; Zugriff über pgx/v5 und sqlc-generierte, typisierte SQL-Abfragen. | Fachobjekte, Jobs, Outbox, Audit, Rohdaten und Suchindizes. |
| Migrationen | Vorwärtsgerichtete, versionierte SQL-Migrationen mit goose, eingebettet in die Binaries. | Reproduzierbarer Schemaaufbau und nachvollziehbare Datenänderungen. |
| Web | Go-Templates und progressive HTML-Interaktion; CSS-Build als versioniertes Artefakt. | Dashboard, Triage, Details, Quellenmonitor und Administration. |
| CLI | Go-CLI mit konsistenter Unterbefehlsstruktur. | Importe, Reprocessing, Demo-Seeding, Wartung und Diagnose. |
| Authentisierung | OIDC Authorization Code Flow mit PKCE; validierte Bearer Tokens für API und Automation. | Browser, menschliche CLI-Nutzung und technische Identitäten. |
| Observability | Strukturierte Logs, Prometheus-kompatible Metriken und OpenTelemetry-kompatible Traces. | Betrieb, Fehleranalyse und Leistungsnachweise. |
| Bereitstellung | OCI-Container, Compose für lokal und versionierte Konfiguration für private Demo. | Reproduzierbare Laufzeitumgebungen. |

### 3.2 Repository-Struktur

```
/cmd
  /risksignal-server       # API und Web
  /risksignal-worker       # Jobs, Scheduler, Outbox
  /risksignal              # CLI
/internal
  /domain                  # Entitäten, Werteobjekte, Regeln
  /application             # Use Cases, Ports, Transaktionen
  /adapters
     /httpapi /web /cli
     /postgres /oidc /notify
     /sources/nvd /sources/kev /sources/epss
  /platform                # Konfiguration, Logging, Health
/api/openapi               # OpenAPI-Vertrag
/db/migrations /db/queries
/web/templates /web/assets
/testdata /docs /deploy
```

Pakete unter internal verhindern eine unkontrollierte externe Verwendung. Domänenmodule dürfen keine Adapter importieren. Abhängigkeiten zeigen von aussen nach innen; konkrete Adapter implementieren Ports der Anwendungsschicht.

### 3.3 Konfigurationsprinzip

- Konfiguration erfolgt über versionierte Defaults, Umgebungsvariablen und optional eingehängte Konfigurationsdateien.
- Geheimnisse werden ausschliesslich zur Laufzeit injiziert und weder im Repository noch in Diagnoseausgaben gespeichert.
- Beim Start werden Pflichtwerte, URLs, Zeitdauern und gegenseitig ausschliessende Modi validiert.
- Produktions- oder Demo-Online-Modus verweigert den Start, wenn der lokale Authentisierungs-Bypass aktiviert ist.
- Sicherheitsrelevante Konfigurationswerte werden mit Herkunft, jedoch ohne geheimen Inhalt, im Startprotokoll ausgewiesen.

---

## 4. Laufzeit- und Bereitstellungsarchitektur

Aus demselben Quellstand entstehen drei ausführbare Programme. Server und Worker dürfen für die lokale Demo gemeinsam gestartet werden; ihre Verantwortungen bleiben im Code getrennt. In der privaten Online-Demo laufen sie als getrennte Prozesse beziehungsweise Container.

### 4.1 Prozessrollen

| Prozess | Verantwortung | Skalierungs- und Fehlergrenze |
|---|---|---|
| risksignal-server | REST-API, Weboberfläche, OIDC-Sitzungen, synchrone Anwendungsfälle und Health-Endpunkte. | Zustandslos ausser kurzlebigem Cache; mehrere Instanzen später möglich. |
| risksignal-worker | Quellenabrufe, Normalisierung, Matching, Priorisierung, SLA-Eskalation, Retention, Outbox und Benachrichtigungen. | Jobs werden geleast; ein Abbruch wird nach Lease-Ablauf sicher fortgesetzt. |
| risksignal CLI | Administrative und automatisierte Befehle gegen API oder kontrolliert gegen lokale Wartungsports. | Nicht-interaktiv nutzbar; Exit-Codes und maschinenlesbare Ausgabe. |
| PostgreSQL | Transaktionale Quelle für Fachzustand, Jobs, Audit und Integrationsereignisse. | Regelmässiges Backup; Restore ist Abnahmekriterium. |

### 4.2 Lokale Umgebung

- Compose startet PostgreSQL, Server, Worker, lokalen OIDC-Testanbieter und Mail-Testserver.
- Ein Seed-Befehl erzeugt Benutzerrollen, synthetisches Inventar, Quellenstände und erwartete P1-P4-Signale.
- Persistente Volumes können für einen vollständigen Neustart bewusst beibehalten oder explizit neu erzeugt werden.
- Standardmässig werden nur Loopback-Ports veröffentlicht. Externe Erreichbarkeit ist eine bewusste Konfigurationsänderung.

### 4.3 Private Online-Demoumgebung

- Ein gehärteter Linux-Einzelhost betreibt Reverse Proxy, Server, Worker und PostgreSQL in getrennten Containern.
- Nur HTTPS ist öffentlich erreichbar. Datenbank, Worker, Verwaltungsports und Metriken sind nicht direkt exponiert.
- OIDC ist verpflichtend; Rollen werden aus freigegebenen Claims auf interne Rollen abgebildet.
- Backups werden verschlüsselt und ausserhalb des Laufzeithosts abgelegt. Restore-Tests erfolgen wiederkehrend.
- Die Umgebung verwendet ausschliesslich synthetische oder ausdrücklich freigegebene Inventardaten.

### 4.4 Deployment-Ablauf

1. Build erzeugt signierbare, unveränderliche Container-Images und eine SBOM.
2. Vor dem Rollout werden Datenbanksicherung, Konfigurationsvalidierung und Migrationsplan geprüft.
3. Migrationen laufen einmalig unter einer Advisory Lock. Vor jedem Lauf werden die Hashes der bereits angewendeten Migrationen gegen die eingebetteten Dateien geprüft; jede Abweichung bricht den Start ab (Tabelle schema_migration_log, ADR-010).
4. Server und Worker werden mit Health- und Readiness-Prüfungen aktualisiert.
5. Smoke-Tests prüfen Anmeldung, API, Quellenmonitor und einen lesenden Signalabruf.
6. Rollback verwendet das vorherige Image. Nicht abwärtskompatible Datenmigrationen benötigen einen eigenen Rücksetzungsplan.

---

## 5. Anwendungskomponenten

| Komponente | Kernverantwortung | Wichtige Ausgaben |
|---|---|---|
| Source Registry | Quellenkonfiguration, Zeitplan, Cursor, Status und Abrufhistorie. | SourceRun, Rohdatensatz, Health-Status. |
| Ingestion | HTTP-Abruf, technische Validierung, Hashing, Dekompression und Quarantäne. | Unveränderter Payload, Importmetrik, Fehlergrund. |
| Normalization | Quellenspezifische Felder in Schwachstelle, Evidenz, Produkt und Bewertung überführen. | Versionierte normalisierte Objekte. |
| Inventory | Assets, Komponenten, Importe, Datenqualität und Lebenszyklus verwalten. | Aktueller Inventarstand und Importreport. |
| Matching | Komponenten gegen Produkt- und Versionsangaben abgleichen. | Zuordnung, Methode, Konfidenz und Begründung. |
| Prioritization | P1-P4 aus Evidenz, Zuordnung und Assetkontext ableiten. | Priorität, Faktorenset und Regelversion. |
| Signal Workflow | Status, Owner, Fristen, Kommentare und menschliche Entscheidungen. | Risikosignal und Zustandsereignisse. |
| SLA | Reaktionsziele, verbleibende Zeit, Pausen, Verletzungen und Eskalationen. | Deadlines und SLA-Ereignisse. |
| Notification | Benachrichtigungen vorbereiten und über Adapter zustellen. | In-App-, Mail- oder Webhook-Zustellung. |
| Audit & Retention | Nachweise unveränderbar protokollieren und Aufbewahrungsregeln vollziehen. | Auditereignisse und Löschprotokolle. |

### 5.1 Transaktionsgrenzen

Jeder fachliche Befehl wird in genau einer Datenbanktransaktion verarbeitet. Zustandsänderung, Auditereignis und zugehöriges Outbox-Ereignis werden atomar gespeichert. Externe Zustellungen erfolgen erst nach Commit. Dadurch kann ein fehlgeschlagener Mail-, Webhook- oder späterer Ticketing-Aufruf den fachlichen Zustand nicht teilweise zurücksetzen.

### 5.2 Fehlersemantik

- Validierungsfehler: fachlich verständliche Meldung mit Feldbezug; keine Wiederholung.
- Konflikt: Optimistic-Locking- oder Zustandskonflikt; Client liest den aktuellen Stand und entscheidet erneut.
- Temporärer Infrastrukturfehler: begrenzte Wiederholung mit Backoff und Jitter.
- Dauerhafter Integrationsfehler: Quarantäne beziehungsweise Dead-Letter-Zustand mit manueller Wiederaufnahme.
- Unerwarteter interner Fehler: neutrale externe Meldung mit Korrelations-ID; technische Details nur im geschützten Log.

---

## 6. Domänen- und Datenmodell

Das Domänenmodell trennt externe Aussagen, autorisierten Inventarkontext und daraus abgeleitete Arbeitseinheiten. Eine externe Meldung wird niemals direkt zum Beweis einer konkreten Betroffenheit. Erst eine nachvollziehbare Zuordnung zwischen Schwachstelle und Komponente erzeugt ein Risikosignal.

### 6.1 Aggregate und Verantwortungen

| Aggregat | Identität und Zustand | Konsistenzregeln |
|---|---|---|
| Source | source_id; Typ, URL, Zeitplan, Aktivstatus, Vertrauensprofil und Cursor. | Nur freigegebene Typen; Änderungen auditiert; Geheimnisse nur als Referenz. |
| SourceRun | run_id; Quelle, Start/Ende, Cursor, Zähler, Ergebnis und Fehler. | Genau ein Endzustand; Cursor erst nach erfolgreichem Commit fortschreiben. |
| Vulnerability | vulnerability_id; CVE, Beschreibungen, CVSS und Referenzen. | CVE normalisiert und eindeutig; Quellenaussagen bleiben getrennte Evidenzen. |
| Evidence | evidence_id; Typ, Aussage, Quelle, Gültigkeitszeit, Rohdatenreferenz und Hash. | Unveränderbar; Korrekturen erzeugen neue Version oder neue Evidenz. |
| Asset | asset_id; Name, Typ, Umgebung, Kritikalität, Exposition, Owner und Lebenszyklus. | ID je Inventarquelle eindeutig; deaktivierte Assets bleiben historisch referenzierbar. |
| Component | component_id; Asset, Hersteller, Produkt, Version, CPE, Alias, Image/Digest. | Gehört genau zu einem Asset; Identifier werden normalisiert, Original bleibt erhalten. |
| Match | match_id; Komponente, Schwachstelle, Methode, Konfidenz, Gründe und Regelversion. | Automatische Neuberechnung überschreibt keine menschliche Entscheidung. |
| RiskSignal | signal_id; Match, Priorität, Status, Owner, Fristen und Entscheidung. | Erlaubte Statusübergänge; fachliche Übersteuerung nur mit Begründung. |
| SLAClock | sla_clock_id; Zieltyp, Start, Deadline, Pause, Erfüllung und Verletzung. | Deadline reproduzierbar; Pause nur berechtigt und begründet. |
| AuditEvent | audit_id; Akteur, Zeit, Aktion, Ziel, vorher/nachher und Korrelations-ID. | Append-only; keine fachliche Löschung vor Ende der Aufbewahrung. |

### 6.2 Wertobjekte und kontrollierte Vokabulare

| Wertobjekt | Zulässige Werte / Format | Bemerkung |
|---|---|---|
| AssetType | server_vm, application_framework, container_image, network_security, cloud_saas | Erweiterbar durch Migration und API-Versionierung. |
| Environment | production, staging, test, development, unknown | Produktiv erhöht nicht automatisch die Priorität, ist aber sichtbarer Kontext. |
| Criticality | critical, high, normal, low, unknown | Unknown führt zu Datenqualitätswarnung. |
| Exposure | internet, internal, isolated, unknown | Unknown darf nicht als intern interpretiert werden. |
| Confidence | high, medium, low, none | Aus einem nachvollziehbaren Matching-Score abgeleitet. |
| Priority | P1, P2, P3, P4 | Regelversion und beitragende Faktoren werden gespeichert. |
| SignalStatus | new, in_review, action_planned, resolved, accepted, not_affected | Statuswechsel gemäss Zustandsmatrix. |
| Timestamp | UTC, RFC 3339 nach aussen | Oberfläche lokalisiert Anzeige, nicht Speicherung. |
| MatchMethod | exact_identifier, container_digest, alias_exact_version, canonical_product_range, product_uncertain_version, controlled_alias_only, candidate, no_match | Autoritatives Feld; Konfidenz wird daraus abgeleitet (ADR-015). |

### 6.3 Signal-Zustandsmodell

| Von | Nach | Bedingung |
|---|---|---|
| new | in_review | Analyst oder berechtigter Verantwortlicher übernimmt die Prüfung. |
| new / in_review | action_planned | Betroffenheit plausibel oder bestätigt; Owner und nächste Massnahme vorhanden. |
| new / in_review | not_affected | Begründung und fachliche Evidenz dokumentiert. |
| in_review / action_planned | accepted | Akzeptanzentscheid, Begründung, Entscheider und optional Gültigkeitsfrist vorhanden. |
| action_planned | resolved | Massnahme oder Verifikation dokumentiert; Abschlusszeit wird gesetzt. |
| resolved / accepted / not_affected | in_review | Wiedereröffnung mit Begründung; neue SLA-Behandlung gemäss Regel. |

Abgeschlossene Zustände sind resolved, accepted und not_affected. Der Abschlusszeitpunkt startet die fünfjährige Aufbewahrungsfrist. Eine Wiedereröffnung beendet den laufenden Retention-Countdown und erzeugt ein neues Auditereignis.

---

## 7. Datenbank- und Persistenzkonzept

PostgreSQL ist die transaktionale Quelle des MVP. Normalisierte Fachdaten werden relational modelliert; unveränderte externe Nutzdaten können zusätzlich als JSONB beziehungsweise komprimierte Rohdaten gespeichert werden. Datenbank-Constraints sichern zentrale Invarianten unabhängig von der Anwendung.

### 7.1 Kernschema

| Tabelle | Schlüssel / zentrale Spalten | Indizes und Constraints |
|---|---|---|
| sources | id, type, name, endpoint, schedule, enabled, cursor, config | unique(type, name); URL- und Typprüfung. |
| source_runs | id, source_id, started_at, finished_at, status, counters, cursor_before/after | index(source_id, started_at desc); gültiger Endzustand. |
| raw_records | id, source_id, external_id, content_hash, payload, fetched_at | unique(source_id, external_id, content_hash); Hashindex. |
| vulnerabilities | id, cve_id, summary, published_at, modified_at | unique(cve_id); Volltextindex optional. |
| evidences | id, vulnerability_id, raw_record_id, type, observed_at, value | unique(raw_record_id, type, value_hash). |
| assets | id, external_id, source, type, name, environment, criticality, exposure, owner | unique(source, external_id); Filterindizes. |
| components | id, asset_id, vendor, product, version, cpe, purl, image, digest | index auf normalisierten Produktfeldern, CPE, purl und Digest. |
| matches | id, vulnerability_id, component_id, method, score, confidence, rule_version | unique(vulnerability_id, component_id, rule_version). |
| risk_signals | id, match_id, priority, status, owner, due_at, closed_at, version | Arbeitslistenindizes; optimistic locking über version. |
| sla_clocks | id, signal_id, target, started_at, deadline_at, fulfilled_at, paused_seconds | unique(signal_id, target); Deadline-Index. |
| audit_events | id, aggregate_type/id, actor, action, occurred_at, before/after, correlation_id | Append-only; index Ziel und Zeit. |
| jobs / outbox | id, type, payload, status, available_at, lease_until, attempts, dedupe_key | unique(dedupe_key); index(status, available_at). |
| schema_migration_log | version, file_hash, applied_at, duration_ms | unique(version); Abweichung blockiert den Start. |
| epss_current | cve_id, score, percentile, model_version, loaded_at | unique(cve_id); keine Fremdschlüssel auf diese Tabelle. |
| epss_history | cve_id, observed_on, score, percentile, model_version | unique(cve_id, observed_on); nur CVEs mit Inventarbezug. |
| alias_rules | id, scope, from_value, to_value, version, enabled | unique(scope, from_value, version); versioniert, auditierbar. |
| decision_rules | id, type, target_scope, reason, actor_id, valid_from/until, version | Übersteht die automatische Neuberechnung; auditierbar. |
| priority_rules | rule_id, version, definition, enabled, effective_from | unique(rule_id, version); stabile Regel-ID. |

### 7.2 Identitäten und Zeit

- Interne Primärschlüssel sind zeitlich ungeordnete UUIDs oder ein gleichwertiges nicht erratbares Format.
- Externe IDs werden separat gespeichert und niemals als alleiniger interner Primärschlüssel verwendet.
- Alle Zeitstempel werden als timestamptz in UTC gespeichert. Fachliche Quelldaten behalten zusätzlich ihren Originalzeitpunkt.
- Die Systemuhr wird über einen injizierbaren Clock-Port verwendet, damit SLA- und Retention-Tests ohne reales Warten möglich sind.

### 7.3 Transaktionen, Nebenläufigkeit und Idempotenz

- Schreibende API-Befehle verwenden optimistic locking. Veraltete Versionen ergeben HTTP 409 statt stiller Überschreibung.
- Importe verwenden natürliche Eindeutigkeiten und Inhalts-Hashes. Identische Quelldaten erzeugen keine neuen Fachobjekte.
- Worker reservieren Jobs mit Datenbank-Locks und zeitlich begrenzten Leases. Abgelaufene Leases werden wieder verfügbar.
- Outbox-Ereignisse werden in derselben Transaktion wie der Fachzustand geschrieben und mindestens einmal zugestellt.
- Empfänger verarbeiten Ereignisse idempotent anhand einer unveränderlichen Event-ID oder eines Deduplizierungsschlüssels.

### 7.4 Migrationen und Datenpflege

- Jede Schemaänderung ist eine nummerierte, unveränderliche SQL-Migration im Repository.
- Migrationen laufen vor Applikationsstart und werden mit Prüfsumme protokolliert.
- Destruktive Änderungen folgen Expand-Migrate-Contract: neue Struktur einführen, Daten migrieren, Nutzung umstellen, alte Struktur später entfernen.
- Produktive Datenbereinigungen sind versionierte, wiederholbare Wartungsbefehle mit Dry-Run, Zählern und Auditnachweis.

---

## 8. Quellenintegration und Verarbeitung

Jeder Quellenadapter implementiert denselben Port: Planen, Abrufen, technische Metadaten liefern, Datensätze streamen und einen reproduzierbaren Cursor fortschreiben. Parser erzeugen zunächst quellenspezifische DTOs; erst der Normalizer bildet Domänenobjekte.

### 8.1 Allgemeine Verarbeitungskette

1. Quelle und Abrufparameter aus freigegebener Konfiguration laden.
2. HTTP-Anfrage mit Timeout, User-Agent, optionalem API-Key sowie begrenztem Retry ausführen.
3. Antwortstatus, Content-Type, Grösse und technische Integrität validieren.
4. Rohinhalt unverändert oder nachvollziehbar komprimiert speichern und hashen. Bei Bulk-Dateiquellen ist ein Rohdatensatz die Datei, nicht die Zeile: external_id ist der Dateiname oder das Datum, der Payload die komprimierte Datei; Zeilen werden beim Parsen streamend verarbeitet.
5. Datensätze streamend parsen; einzelne Fehler mit Position und Grund in Quarantäne stellen.
6. Datensätze normalisieren, vorhandene Fachobjekte idempotent aktualisieren und Evidenzen versionieren.
7. Betroffene Produktzuordnungen über einen Kandidaten-Vorfilter gegen den Inventar-Produktindex ermitteln; nur Treffer erzeugen Jobs. Bulk-Läufe erzeugen einen matching.rebuild statt einzelner Jobs.
8. Laufstatistik, Cursor und Datenalter committen; anschliessend Matching-Jobs auslösen.

### 8.2 NVD/CVE-Adapter

- Verwendet die NVD Vulnerability API 2.0 und inkrementelle Zeitfenster auf dem letzten Änderungszeitpunkt.
- Paginierung wird vollständig verarbeitet. Cursor wird erst nach einem erfolgreichen Lauf fortgeschrieben.
- Ein kleines Überlappungsfenster verhindert Lücken an Zeitgrenzen; Idempotenz entfernt Wiederholungen.
- CVE-ID, Beschreibungen, CVSS-Metriken, CPE-Konfigurationen, Referenzen, Publikations- und Änderungszeit werden übernommen.
- NVD-Rate-Limits werden respektiert. API-Key ist optional konfigurierbar und wird ausschliesslich als Secret injiziert.

### 8.3 CISA-KEV-Adapter

- Lädt den offiziellen KEV-Katalog als versionierten Gesamtdatenbestand.
- Der gesamte Inhalt erhält einen Hash; unveränderte Dateien werden als erfolgreicher Lauf ohne fachliche Änderungen verbucht.
- CVE-ID, Hersteller, Produkt, Schwachstellenname, Aufnahmedatum, bekannte Ausnutzung, erforderliche Massnahme und Frist werden als Evidenz gespeichert.
- Entfernte oder geänderte Katalogeinträge werden historisiert und nicht stillschweigend aus bestehenden Entscheidungen entfernt.

### 8.4 FIRST-EPSS-Adapter

Für den täglichen Massenabgleich wird die vollständige tägliche CSV-Datei von https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz verwendet. Die EPSS-API unter api.first.org bleibt für gezielte Einzelabfragen und Diagnose vorgesehen; FIRST weist ausdrücklich darauf hin, dass die API nicht für die laufende Bulk-Synchronisation gedacht ist.

- CSV wird streamend dekomprimiert und verarbeitet; Download muss nicht vollständig im Arbeitsspeicher liegen.
- CVE, Wahrscheinlichkeit, Perzentil, Publikationsdatum und Modellversion werden gespeichert.
- epss_current wird in einer Transaktion über TRUNCATE + COPY ersetzt; epss_history wird aus demselben Lauf über den Kandidaten-Vorfilter gespeist.
- TRUNCATE nimmt eine ACCESS-EXCLUSIVE-Sperre; Lesen auf epss_current blockiert für die Dauer des Ladens. Angesichts der kleinen Benutzerzahl bewusst akzeptiert; im Betriebshandbuch dokumentiert.
- Historische Werte werden nur für CVEs mit relevantem Inventarbezug dauerhaft fortgeschrieben; der aktuelle Vollbestand bleibt ersetzbar.
- Fehlende Werte werden als fehlend und nicht als null Prozent interpretiert.

### 8.5 Synthetische Quelle und BACS/NCSC-Erweiterung

Die synthetische Quelle implementiert denselben Adaptervertrag und liefert deterministische Referenzfälle für alle Prioritäten, Matching-Konfidenzen und Fehlerzustände. Nach dem MVP wird BACS/NCSC Schweiz als erster zusätzlicher Adapter umgesetzt. Bevorzugt werden strukturierte offizielle Feeds oder APIs. Fehlen diese, wird ein kontrollierter manueller Import mit Herkunftsnachweis umgesetzt; aggressives Web-Scraping ist ausgeschlossen.

### 8.6 Quarantäne und Wiederverarbeitung

| Status | Bedeutung | Aktion |
|---|---|---|
| new | Datensatz konnte nicht verarbeitet werden. | Fehlergrund, Quelle, Position und Payload-Hash anzeigen. |
| acknowledged | Administrator hat den Fehler bewertet. | Kommentar und Verantwortlichkeit erfassen. |
| ready_for_retry | Adapter, Regel oder Daten wurden korrigiert. | Gezielte Wiederverarbeitung mit neuer Parser-/Regelversion. |
| resolved | Datensatz erfolgreich verarbeitet oder begründet verworfen. | Ergebnis und Verbindung zum neuen Fachobjekt dokumentieren. |

---

## 9. Matching, Priorisierung und SLA

Matching und Priorisierung sind zwei getrennte Schritte. Matching beantwortet, wie verlässlich eine Schwachstelle einer inventarisierten Komponente zugeordnet werden kann. Priorisierung bewertet anschliessend die Dringlichkeit unter Einbezug von Ausnutzung, technischer Schwere und Assetkontext.

### 9.1 Normalisierung von Produktdaten

- Hersteller- und Produktnamen werden Unicode-normalisiert, getrimmt und für Vergleiche kleingeschrieben; Originalwerte bleiben erhalten.
- Punktuation, bekannte Rechtsformen und kontrollierte Schreibvarianten werden über versionierte Aliasregeln in der Tabelle alias_rules behandelt.
- CPE und Package URL werden syntaktisch validiert und in ihre Bestandteile zerlegt.
- Container-Images werden in Registry, Repository, Tag und Digest zerlegt. Ein Digest ist stärker als ein veränderlicher Tag.
- Versionen werden nicht lexikografisch verglichen. Der Adapter wählt je Produkttyp eine geeignete Semantik; unbekannte Formate reduzieren die Konfidenz.

### 9.2 Matching-Stufen

| Methode | Voraussetzung | Konfidenz | Sortierrang |
|---|---|---|---|
| exact_identifier | CPE oder purl stimmt und Version liegt eindeutig im betroffenen Bereich. | high | 100 |
| container_digest | Image-Repository und unveränderlicher Digest stimmen mit gesicherter Evidenz. | high | 95 |
| alias_exact_version | Kontrollierter Hersteller-/Produktalias und exakte Version stimmen. | high | 90 |
| canonical_product_range | Normalisiertes Produkt stimmt; Version liegt nachweisbar im Bereich. | high | 80 |
| product_uncertain_version | Produkt stimmt; Version fehlt oder Bereich ist nicht eindeutig interpretierbar. | medium | 65 |
| controlled_alias_only | Kontrollierter Alias stimmt, Versionsbezug fehlt. | medium | 55 |
| candidate | Nur schwache Namensähnlichkeit oder unvollständige Evidenz. | low | berechnete Ähnlichkeit |
| no_match | Produkt oder Version ist nachweislich nicht betroffen. | none | 0 |

Der Methode ist das autoritative Feld; die Konfidenz wird daraus über eine versionierte Zuordnung abgeleitet. Der Score ist für deterministische Methoden ein fester, aus der Methode abgeleiteter Sortierrang; nur für candidate wird eine tatsächlich berechnete Ähnlichkeit verwendet. Fuzzy Matching erzeugt nur Kandidaten und nie automatisch eine hohe Konfidenz. Manuelle Korrekturen und Ausschlussregeln werden in der Tabelle decision_rules gespeichert. Eine Ausschlussregel benötigt Begründung, Gültigkeitsbereich und Urheber; sie bleibt auch nach einer automatischen Neuberechnung wirksam, bis sie abgelaufen oder aufgehoben ist.

### 9.3 Deterministische Prioritätsregeln

| Klasse | Regel des MVP | Hinweis |
|---|---|---|
| P1 | Konfidenz high UND KEV=true UND (Kritikalität critical/high ODER Exposition internet). | Aktive Benachrichtigung und sofortige SLA-Uhr. |
| P2 | Konfidenz high UND mindestens einer: KEV, CVSS >= 9.0, EPSS-Perzentil >= 0.95; ODER Konfidenz medium UND KEV UND kritischer/exponierter Kontext. | Zeitnahe Bewertung; Unsicherheit bleibt sichtbar. |
| P3 | Plausible Zuordnung mit medium/low oder high ohne starken Dringlichkeitsindikator. | Zusätzliche Abklärung erforderlich. |
| P4 | Keine bestätigte Inventarzuordnung oder rein informativer Hinweis. | Beobachtung; keine Betroffenheitsbehauptung. |

Die Regeln werden als versionierte Konfiguration mit stabiler Regel-ID in der Tabelle priority_rules gespeichert. Jedes Signal enthält den verwendeten Regelstand und die einzelnen Faktoren. Eine fachliche Umstufung setzt Begründung, Akteur und Zeit; der berechnete Ausgangswert bleibt sichtbar.

### 9.4 SLA-Uhren

| Priorität | Benachrichtigung | Bestätigung | Bewertung | Entscheid |
|---|---|---|---|---|
| P1 | 5 Min. | 15 Min. | 60 Min. | 4 Std. |
| P2 | 15 Min. | 1 Std. | 4 Std. | 24 Std. |
| P3 | Kein Paging | 24 Std. | 72 Std. | Nach Bewertung |
| P4 | Kein Paging | Keine einzelne | Wöchentlich | Bei Bedarf |

- SLA-Start ist der Zeitpunkt, an dem ein neues oder höher priorisiertes Signal fachlich committed wurde.
- Eine Heraufstufung erzeugt fehlende strengere SLA-Uhren ab Heraufstufungszeit; bereits verstrichene Bearbeitungszeit bleibt im Audit sichtbar.
- Bestätigung erfolgt explizit durch eine berechtigte Person. Reines Öffnen der Detailseite genügt nicht.
- Eine Pause setzt Grund, Akteur und optional erwartetes Ende voraus. Pausen werden nicht rückwirkend erfasst.
- P1 wird bei fehlender Bestätigung nach 15 Minuten einmalig eskaliert und danach gemäss konfigurierter Wiederholungsregel erinnert.
- Demo-Zeitprofile skalieren nur Dauern; Status-, Eskalations- und Auditlogik bleiben identisch.

### 9.5 Neuberechnung und Stabilität

Neue Evidenz oder Inventaränderungen erzeugen gezielte Recompute-Jobs. Eine Prioritätsänderung wird nur gespeichert, wenn sich Faktorenset, Regelversion oder Ergebnis verändert. Geschlossene Signale werden bei neuer relevanter Evidenz nicht still geändert; das System erzeugt einen Wiedereröffnungsvorschlag oder ein neues Signal gemäss Deduplizierungsregel.
---

## 10. API-Konzept

Die API ist der vollständige externe Fachvertrag. Sie wird schema-first mit OpenAPI 3.1 beschrieben. Browser- und CLI-Adapter teilen die gleichen Anwendungsdienste; automatisierte Integrationen können alle fachlichen MVP-Funktionen über die API ausführen.

### 10.1 Konventionen

- Basis-Pfad /api/v1; Breaking Changes erfordern eine neue Major-API-Version.
- JSON-Feldnamen in snake_case; Zeitangaben in RFC 3339 UTC; IDs als Strings.
- Listen verwenden cursorbasierte Pagination, stabile Sortierung und explizite Filter.
- Schreibbefehle akzeptieren Idempotency-Key, wo Wiederholung durch Clients realistisch ist; Idempotency-Key und If-Match sind als Header-Parameter im OpenAPI-Dokument deklariert, nicht nur als Prosa.
- Optimistic Locking erfolgt mit Version beziehungsweise ETag/If-Match.
- Fehler folgen RFC 9457 Problem Details und enthalten type, title, status, detail, instance und correlation_id; Problem Details sind eine wiederverwendbare Schema-Komponente im OpenAPI-Dokument.
- OpenAPI-Dokument und Beispiele werden im Build validiert; Implementierung und Vertrag werden durch Contract-Tests abgeglichen.

### 10.2 Ressourcen und Kernendpunkte

| Ressource | Endpunkte | Zweck |
|---|---|---|
| System | GET /health/live; GET /health/ready; GET /version | Betriebsprüfung und Build-Nachweis. |
| Sources | GET/POST /sources; GET/PATCH /sources/{id}; POST /sources/{id}/runs | Quellen verwalten und Läufe starten. |
| Runs | GET /source-runs; GET /source-runs/{id}; POST /source-runs/{id}/retry | Importstatus, Zähler und kontrollierte Wiederholung. |
| Quarantine | GET /quarantine; GET/PATCH /quarantine/{id}; POST /quarantine/{id}/reprocess | Fehler bewerten und erneut verarbeiten. |
| Inventory | POST /inventory/imports; GET /inventory/imports/{id}; POST /inventory/imports/{id}/commit | Voransicht, Validierung und bestätigter Import. |
| Assets | GET /assets; GET/PATCH /assets/{id}; GET /assets/{id}/components | Inventar suchen, prüfen und verwalten. |
| Signals | GET /signals; GET /signals/{id}; POST /signals/{id}/commands | Triage, Status, Owner, Kommentar, Umstufung und Abschluss. |
| Audit | GET /audit-events; GET /signals/{id}/audit; POST /audit-events/{id}/reveal-actor | Nachweis nach Ziel, Akteur, Aktion und Zeitraum; Identitätsauflösung berechtigungsgesteuert und selbst-auditiert (ADR-014). |
| Administration | GET /roles; GET/PATCH /users/{id}/roles; GET/PATCH /settings/{key} | Rollen und freigegebene Konfiguration. |
| Exports | POST /exports; GET /exports/{id}; GET /exports/{id}/download | Asynchroner CSV-/JSON-Export mit Filterkontext. |

### 10.3 Command-Endpunkt für Signale

Zustandsänderungen werden als explizite Befehle statt als beliebige Objekt-Patches modelliert. Dadurch bleiben Berechtigungen, Pflichtfelder und Auditsemantik eindeutig.

```http
POST /api/v1/signals/{signal_id}/commands
{
  "command": "change_status",
  "expected_version": 7,
  "status": "action_planned",
  "reason": "Betroffenheit durch Systemverantwortung bestätigt",
  "owner_id": "...",
  "due_at": "2026-09-09T12:00:00Z"
}
```

### 10.4 Filter, Suche und Exporte

- Signalfilter: priority, status, asset_id, asset_type, product, cve, owner_id, source_id, created_from/to, sla_state und free_text.
- Standardsortierung: Priorität aufsteigend P1-P4, danach nächste SLA-Deadline und Erstellzeit.
- Exporte laufen als Jobs, frieren Filter und Erstellzeit ein und enthalten Schema- und Regelversion.
- CSV-Ausgaben neutralisieren führende Formelzeichen. Downloads sind kurzlebig autorisiert und werden auditiert.

### 10.5 API-Berechtigungen

Jeder Endpunkt deklariert mindestens eine Permission. Die Middleware authentisiert, die Anwendungsschicht autorisiert erneut am konkreten Anwendungsfall. Dadurch kann ein alternativer Adapter die Fachberechtigung nicht umgehen. Objektbezogene Einschränkungen - etwa nur zugewiesene Signale für Systemverantwortliche - werden im Query- und Command-Pfad konsistent angewendet.

---

## 11. Browseroberfläche und CLI

Browser und CLI sind gleichwertige Adapter zu denselben Anwendungsfällen. Die Weboberfläche optimiert die tägliche Triage und Administration. Die CLI optimiert wiederholbare, automatisierte und diagnostische Abläufe.

### 11.1 Web-Navigation

| Ansicht | Inhalt | Primäre Aktionen |
|---|---|---|
| Dashboard | Offene Signale nach P1-P4, SLA-Zustand, Alter, Owner, Quellenstatus und Datenqualität. | Filtern, Triage-Liste öffnen, kritische Zustände erkennen. |
| Triage | Dichte, filterbare Signal-Arbeitsliste mit Priorität, CVE, Asset, Konfidenz, Status und Deadline. | Bestätigen, zuweisen, Status setzen, Stapelauswahl für zulässige Aktionen. |
| Signaldetail | Faktoren, Match-Begründung, Evidenzen, Asset/Komponenten-Kontext, SLA und Audit-Timeline. | Entscheiden, kommentieren, umstufen, abschliessen, wiedereröffnen. |
| Quellenmonitor | Letzter Lauf, Datenalter, Zähler, Fehler, Rate-Limit und Quarantäne. | Lauf starten, Fehler anerkennen, Wiederverarbeitung. |
| Inventar | Assets, Komponenten, Importstatus, Datenqualität und letzte Verifikation. | Import vorprüfen/bestätigen, Asset suchen und korrigieren. |
| Administration | Benutzerrollen, Quellen, Regeln, Zeitprofile und Retention-Konfiguration. | Freigegebene Werte ändern; Auswirkungen vor Bestätigung anzeigen. |

### 11.2 UX-Leitplanken

- Priorität wird nie nur durch Farbe vermittelt; Text, Symbol und Begründung sind zusätzlich sichtbar.
- Jede automatische Aussage unterscheidet zwischen bestätigt, wahrscheinlich, möglich und nicht nachgewiesen.
- Destruktive oder weitreichende Aktionen zeigen Zielumfang und erfordern eine Bestätigung.
- Listen behalten Filter in der URL, damit Ansichten reproduzierbar und teilbar bleiben.
- Tastaturnavigation, sichtbarer Fokus, ausreichender Kontrast und semantisches HTML sind Mindestanforderungen.
- Zeitkritische P1/P2-Zustände aktualisieren sich progressiv, ohne die gesamte Seite neu zu laden.

### 11.3 CLI-Befehlsmodell

```
risksignal auth login|status
risksignal source list|run|status
risksignal inventory validate|preview|import
risksignal signal list|show|ack|assign|transition|comment
risksignal quarantine list|ack|reprocess
risksignal export create|download
risksignal maintenance migrate|retention|recompute|identity-lookup|identity-pseudonymize
risksignal demo seed|reset|run
risksignal diagnose config|connectivity|health
```

- Standardausgabe ist menschenlesbar; --output json liefert stabile maschinenlesbare Strukturen.
- Nicht-interaktive Befehle benötigen --yes oder vollständige Parameter und lesen keine verdeckten Defaults aus einem Terminaldialog.
- Exit-Code 0 bedeutet Erfolg; definierte Codes unterscheiden Validierung, Authentisierung, Berechtigung, Konflikt und Infrastrukturfehler.
- Dry-Run ist für Inventarimporte, Retention, Migrationen, Recompute, identity-lookup, identity-pseudonymize und Datenbereinigung verpflichtend.
- CLI-Tokens werden über OIDC bezogen oder als kurzlebige Automation-Credentials injiziert und niemals in Logs ausgegeben.

---

## 12. Identität, Berechtigungen und Sicherheit

Der Identity Provider authentisiert Benutzer; RiskSignal autorisiert Aktionen. Das System speichert nur stabile externe Subject-ID, Anzeigename, optionale E-Mail für Benachrichtigungen, interne Rollen und den letzten Anmeldezeitpunkt. Passwörter werden nicht implementiert oder gespeichert. Benutzer werden deaktiviert, nie gelöscht; ihre interne ID bleibt dauerhaft referenzierbar, damit Auditeinträge auflösbar bleiben (ADR-014).

### 12.1 OIDC-Abläufe

| Nutzung | Ablauf | Sicherheitsvorgaben |
|---|---|---|
| Browser | Authorization Code Flow mit PKCE; Callback erzeugt serverseitige Sitzung. | State, Nonce, PKCE, Issuer, Audience, Signatur und Ablauf prüfen; sichere SameSite-Cookies. |
| Menschliche CLI | Device Authorization Flow, falls der gewählte Provider ihn unterstützt; sonst Browser-Login über Loopback Callback. | Kein Passwort in CLI; Token im geschützten OS Credential Store oder nur im Prozess. |
| Automation | Client Credentials oder Workload Identity mit eng begrenzten Scopes. | Kurzlebige Tokens, Rotation, eindeutige technische Identität und Audit-Akteur. |
| Lokale Entwicklung | Expliziter Dev-Principal nur bei Loopback-Bindung und environment=local. | Startabbruch bei Online-/Demo-Modus, nicht-lokaler Bindung oder fehlendem Schutzflag. |

### 12.2 Rollen- und Permission-Matrix

| Permission | Analyst | Systemverantw. | Admin | Auditor | Product Owner |
|---|---|---|---|---|---|
| signals.read | Ja | Zugeordnet | Ja | Ja | Ja |
| signals.triage | Ja | Zugeordnet | Nein | Nein | Nein |
| signals.override | Ja | Nein | Nein | Nein | Nein |
| inventory.read | Ja | Zugeordnet | Ja | Ja | Ja |
| inventory.manage | Nein | Nein | Ja | Nein | Nein |
| sources.manage | Nein | Nein | Ja | Nein | Nein |
| users.roles.manage | Nein | Nein | Ja | Nein | Nein |
| audit.read | Eigene Fälle | Zugeordnet | Ja | Ja | Ja |
| exports.create | Ja | Zugeordnet | Ja | Ja | Ja |
| settings.approve | Nein | Nein | Nein | Nein | Ja |
| audit.reveal_identity | Nein | Nein | Nein | Ja | Ja |

Die Matrix ist die Ausgangskonfiguration. Objektbezogene Regeln und Vier-Augen-Freigaben können Berechtigungen weiter einschränken, aber nicht implizit erweitern. Administratoren besitzen nicht automatisch fachliche Entscheidungsrechte. Die Auflösung einer Identität ist ein fachlicher Akt, kein betrieblicher; Administratoren besitzen sie daher nicht (ADR-014).

### 12.3 Sicherheitskontrollen

- TLS für alle Online-Verbindungen; sichere Header, restriktive Content Security Policy und Schutz vor Clickjacking.
- CSRF-Schutz für browserbasierte Schreiboperationen; CORS standardmässig deaktiviert und nur explizit freigegeben.
- Strikte Eingabegrenzen für Uploadgrösse, Zeilenanzahl, Freitext, URLs und Filterkomplexität.
- HTML-Ausgabe wird kontextbezogen escaped; CSV-Formelinjektion und Log-Injektion werden neutralisiert.
- SSRF-Schutz: Quellen-URLs stammen nur aus administrativ freigegebener Konfiguration; Redirects und private Zielnetze werden kontrolliert.
- Secrets werden über Laufzeitumgebung oder Secret Store geliefert und in Fehlermeldungen redigiert.
- Abhängigkeiten, Container und SBOM werden automatisiert auf bekannte Schwachstellen geprüft.
- Sicherheitsrelevante Aktionen erzeugen Audit- und optional Alarmereignisse.

### 12.4 Bedrohungsschwerpunkte

| Bedrohung | Gegenmassnahme | Nachweis |
|---|---|---|
| Manipulierter Feed | TLS, Grössen-/Schema-Prüfung, Hash, Quarantäne und getrennte Evidenz. | Adaptertests mit verfälschten Payloads. |
| OIDC-Fehlkonfiguration | Issuer/Audience/Nonce/PKCE-Prüfung und Startvalidierung. | Negative Login- und Token-Tests. |
| Rechteausweitung | Deny-by-default, Permission-Matrix und Autorisierung im Use Case. | Automatisierte Matrix- und Objektbereichstests. |
| CSV-/Formelinjektion | Eingabevalidierung und Neutralisierung beim Export. | Referenzdatei mit gefährlichen Zellanfängen. |
| SSRF über Quellen | Allowlist, DNS/IP-Prüfung, Redirect-Limits und kein freier URL-Abruf. | Tests gegen Loopback, Link-Local und private Netze. |
| Audit-Manipulation | Append-only-Rechte, getrennte DB-Rolle, Hash-Verkettung optional und externe Backups. | DB-Berechtigungstest und Integritätsprüfung. |

---

## 13. Audit, Aufbewahrung und Datenschutz

Auditereignisse dokumentieren fachliche und administrative Entscheidungen. Sie sind nicht dasselbe wie technische Logs. Auditdaten sind für berechtigte Reviewer filterbar und werden zusammen mit abgeschlossenen Signalen fünf Jahre aufbewahrt.

### 13.1 Audit-Ereignismodell

- event_id, occurred_at, actor_type, actor_id und actor_display_name zum Ereigniszeitpunkt; actor_display_name wird als eigenes, selektiv löschbares Feld geführt und nicht in einen strukturierten Blob eingebettet.
- action, aggregate_type, aggregate_id, request_id und correlation_id.
- before und after als minimierte strukturierte Zustandsausschnitte; Geheimnisse und Tokens sind ausgeschlossen.
- reason, source_channel, client_id und optionaler externer Ticketbezug.
- Regel-, Schema- und Anwendungsversion für automatisch erzeugte Entscheidungen.

### 13.2 Auditpflichtige Aktionen

- Anmeldung, fehlgeschlagene oder verweigerte sicherheitsrelevante Zugriffe und Rollenänderungen.
- Quellenaktivierung, Konfigurationsänderung, manueller Lauf und Quarantäne-Wiederverarbeitung.
- Inventarimport, Asset-/Komponentenkorrektur und Datenqualitätsübersteuerung.
- Match-Bestätigung/-Verwerfung, Prioritätsänderung, Status, Owner, Kommentar und Frist.
- SLA-Pause, Erfüllung, Verletzung, Eskalation und Wiedereröffnung.
- Export, Retention-Lauf, Löschsperre, Backup/Restore und spätere Ticket-Synchronisation.
- Identitätsauflösung (audit.identity_revealed) mit Akteur, Ziel, Zeit und zwingender Begründung.

### 13.3 Aufbewahrungsmatrix

| Datenart | Standard | Technische Umsetzung |
|---|---|---|
| Offene Signale | Bis Abschluss | Nicht löschbar durch Retention; Status und Historie bleiben vollständig. |
| Abgeschlossene Signale | 5 Jahre ab closed_at | Monatlicher partitionierbarer Retention-Lauf mit Dry-Run und Freigabe. |
| Audit zum Signal | 5 Jahre ab closed_at | Wird nie vor dem zugehörigen Signal entfernt. |
| Normalisierte Evidenz | Mindestens bis Ende Signalfrist | Referenzprüfung verhindert verfrühte Löschung. |
| Rohdatensätze | Konfigurierbar; Startwert 180 Tage | Hash und notwendige Evidenz bleiben; längere Legal-Hold-Regel möglich. |
| Quarantäne | Konfigurierbar; Startwert 90 Tage nach Abschluss | Offene Einträge werden nicht automatisch entfernt. |
| Technische Logs | Konfigurierbar; Startwert 90 Tage | Zentrale Log-Retention; keine fachliche Nachweisquelle. |
| Security-Logs | Konfigurierbar; Startwert 1 Jahr | Zugriff eingeschränkt; Vorgabe der Zielumgebung hat Vorrang. |
| Anzeigename im Audit | Personenbezogene Frist gemäss TD-08 | Feld wird geleert; Anzeige als User #<Kurz-ID>; Auflösung über actor_id bleibt möglich. |
| Freitext im Audit (reason, Kommentare) | Personenbezogene Frist gemäss TD-08 | Pseudonymisiert oder entfernt; kann personenbezogene Daten Dritter enthalten. |

### 13.4 Retention-Lauf und Pseudonymisierung

Die Pseudonymisierung ist eine eigene Stufe zwischen Aufbewahrung und Löschung: Der Anzeigename wird geleert, Freitext pseudonymisiert oder entfernt. Sie ist durch berechtigte Auflösung reversibel und ausdrücklich keine Anonymisierung.

1. Dry-Run ermittelt Objekte, Referenzen, Grösse und Sperrgründe ohne Änderung.
2. Legal Hold, offene Untersuchung oder Wiedereröffnung sperren die Löschung mit dokumentiertem Grund.
3. Freigegebener Lauf verarbeitet begrenzte Batches und protokolliert Anzahl, Zeitraum und Ergebnis.
4. Löschung erfolgt referenzsicher in definierter Reihenfolge; Fehler stoppen nur den betroffenen Batch.
5. Ein Retention-Report ohne fachliche Inhalte bleibt als Betriebsnachweis erhalten.

### 13.5 Datenschutz und Datenminimierung

Benutzerprofile enthalten nur die für Identität, Rollen, Zuweisung und Benachrichtigung notwendigen Attribute. Inventar-Owner sollen nach Möglichkeit Teams oder Funktionspostfächer sein. Freitext wird durch Hinweise, Längenbegrenzung und Berechtigungen kontrolliert. Exporte enthalten nur angeforderte Felder und werden zeitlich begrenzt bereitgestellt. Da die Pseudonymisierung reversibel ist, bleiben Auditdaten für die gesamte Aufbewahrungsfrist personenbezogene Daten; der Schutz beruht auf Zugriffskontrolle und nicht auf einer Frist (siehe TD-08).

---

## 14. Hintergrundverarbeitung und Benachrichtigungen

Zeitgesteuerte und potenziell langlaufende Aufgaben werden als persistente Jobs verarbeitet. Die Queue liegt im MVP in PostgreSQL. Fachliche Ereignisse gelangen über eine transaktionale Outbox zu Benachrichtigungs- und Integrationsadaptern.

### 14.1 Jobtypen

| Jobtyp | Auslöser | Idempotenzschlüssel |
|---|---|---|
| source.fetch | Zeitplan oder manueller Start. | source_id + planzeit/manuelle request_id |
| source.normalize | Neue Raw Records. | raw_record_id + normalizer_version |
| inventory.import | Bestätigter Import. | import_id |
| matching.rebuild | Erstimport oder Regelversionswechsel. | rule_version + inventory_snapshot |
| matching.recompute | Neue Evidenz, Komponenten- oder Regeländerung. | Hash über die sortierte vulnerability_id-Liste + component_scope + rule_version (Batch, Richtwert 500) |
| priority.recompute | Match-, Evidenz-, Asset- oder Regeländerung. | signal_scope + rule_version + input_hash |
| sla.evaluate | Minütlicher Scheduler und fachliches Ereignis. | clock_id + deadline_type |
| notification.deliver | Outbox-Ereignis. | notification_id + channel + recipient |
| export.generate | Exportauftrag. | export_id |
| retention.execute | Freigegebener Wartungsplan. | policy_id + cutoff + batch |

### 14.2 Retry- und Dead-Letter-Regeln

- Nur als temporär klassifizierte Fehler werden automatisch wiederholt.
- Backoff ist exponentiell mit Jitter und besitzt pro Jobtyp eine maximale Versuchszahl.
- Rate-Limit-Antworten respektieren Retry-After und werden nicht als technischer Fehler der Quelle gewertet.
- Nach dem letzten Versuch wechselt der Job in dead_letter. Ursache, Payload-Referenz und letzte Fehlermeldung bleiben sichtbar.
- Manuelle Wiederaufnahme erzeugt einen neuen Versuch mit Referenz auf den ursprünglichen Job und wird auditiert.
- unique(dedupe_key) bleibt während der gesamten Laufzeit eines Jobs in Kraft — nicht nur bis zur Reservierung.

### 14.3 Benachrichtigungskanäle

| Kanal | MVP-Verwendung | Zustellnachweis |
|---|---|---|
| In-App | Alle P1/P2 und persönliche Zuweisungen; sichtbar im Browser. | created, seen_at, acknowledged_at. |
| E-Mail/SMTP | Aktive P1/P2-Benachrichtigung und Eskalation in Demo/kleinem Betrieb. | accepted/rejected durch SMTP; keine Garantie der menschlichen Kenntnisnahme. |
| Webhook | Optionale Integration in Teams, ChatOps oder Automationen. | HTTP-Status, Versuch, Antwortzeit und letzte Fehlermeldung. |
| Pager-/On-Call-Adapter | Spätere Produktionsausbaustufe. | Provider-Ereignis-ID und Zustellstatus. |

Benachrichtigung und Bestätigung bleiben getrennt. Eine erfolgreiche technische Zustellung erfüllt nicht automatisch die SLA-Bestätigung. Inhalte werden minimiert; Links führen nach Authentisierung zum Signal.

---

## 15. Ticketing-Vorbereitung

Eine konkrete Ticketing-Integration ist nicht Teil des MVP. Die Architektur stellt jedoch einen stabilen Port, Integrationsereignisse und ein Verknüpfungsmodell bereit, sodass ein späterer Adapter keine fachliche Kernlogik verändern muss.

### 15.1 Führende Systeme

| Information | Führendes System | Synchronisation |
|---|---|---|
| Priorität, Betroffenheit, Evidenz, Match-Konfidenz | RiskSignal | Als Kontext zum Ticket; externe Änderung darf RiskSignal nicht still überschreiben. |
| Operative Behebungsaufgabe, Bearbeiter, Sprint/Queue | Ticketing-System | Als Referenz und operativer Status zu RiskSignal. |
| Verknüpfung und letztes Mapping | RiskSignal | Ticket-ID, System, URL, Sync-Version und letzter erfolgreicher Zeitpunkt. |
| Gemeinsamer Status | Gemäss Mapping je Zustand | Nur eindeutig abbildbare Übergänge werden automatisch ausgeführt. |

### 15.2 Ticketing-Port

```go
type TicketingPort interface {
    CreateTicket(ctx context.Context, cmd CreateTicket) (ExternalTicket, error)
    GetTicket(ctx context.Context, ref TicketRef) (ExternalTicket, error)
    UpdateStatus(ctx context.Context, cmd UpdateTicketStatus) error
    AddComment(ctx context.Context, cmd AddTicketComment) error
}

type TicketLink struct {
    SignalID, System, ExternalID, URL, MappingVersion string
    LastSyncedAt time.Time
}
```

### 15.3 Synchronisationsregeln

- Ausgehende Änderungen werden über die Outbox gesendet und mit Event-ID idempotent verarbeitet.
- Eingehende Webhooks werden signaturgeprüft, dedupliziert und zunächst als Integrationsereignis gespeichert.
- Jede Synchronisation enthält die zuletzt bekannte externe Version. Abweichungen erzeugen einen Konflikt statt Last-Write-Wins.
- Ein durch RiskSignal ausgelöstes Update wird anhand Korrelations-ID oder Sync-Marker nicht als neues Gegenereignis zurückgespielt.
- Nicht abbildbare Statuswechsel, gelöschte Tickets und Berechtigungsfehler werden sichtbar und einer manuellen Triage zugewiesen.
- Automatische Erstellung von P1/P2-Tickets bleibt deaktiviert, bis Zielsystem, Mapping und Freigabe separat beschlossen sind.

---

## 16. Observability und Betrieb

RiskSignal stellt technische Telemetrie bereit, ohne Fach- oder Sicherheitsdaten unnötig in Logs zu duplizieren. Korrelations-IDs verbinden API-Anfrage, Job, Quellenlauf, Auditereignis und Benachrichtigung.

### 16.1 Strukturierte Logs

- JSON in Online-Umgebungen, lesbare Ausgabe lokal; einheitliche Felder timestamp, level, service, version, environment und correlation_id.
- Fachobjekte werden nur mit interner ID protokolliert. Tokens, Secrets, komplette Payloads, E-Mail-Inhalte und Freitexte sind ausgeschlossen.
- Fehler enthalten stabile error_code und technische Ursache; Stacktraces nur bei unerwarteten internen Fehlern.
- Sicherheitsereignisse besitzen eigene Kategorie und restriktivere Zugriffs- und Aufbewahrungsregeln.

### 16.2 Metriken

| Metrikgruppe | Beispiele | Zweck |
|---|---|---|
| HTTP | requests_total, duration_seconds, responses_by_status, inflight | Verfügbarkeit und Performance. |
| Quellen | run_duration, records_total, errors_total, data_age_seconds | Aktualität und Adapterqualität. |
| Jobs | queue_depth, oldest_age, attempts, dead_letters | Verarbeitungsrückstand und Fehler. |
| Signale | open_by_priority, sla_remaining, sla_breaches, unassigned | Betriebliche Triagefähigkeit. |
| Datenbank | connections, query_duration, transaction_errors, size | Kapazität und Engpässe. |
| Benachrichtigung | deliveries, failures, retry_age | Aktive Alarmierungsfähigkeit. |

### 16.3 Health und Readiness

- Liveness prüft ausschliesslich, ob der Prozess antwortet; externe Quellen sind kein Liveness-Kriterium.
- Readiness prüft Datenbank, abgeschlossene Migrationen und zwingende Konfiguration.
- Quellenstatus wird separat dargestellt. Eine ausgefallene Quelle macht die Anwendung nicht unbenutzbar, aber sichtbar degraded.
- Worker-Health zeigt Heartbeat, Job-Rückstand und letzte erfolgreiche Scheduler-Ausführung.

### 16.4 Betriebsalarme

| Alarm | Schwelle des MVP | Reaktion |
|---|---|---|
| P1 nicht bestätigt | 15 Minuten reale Zeit. | Fachliche Eskalation gemäss SLA. |
| Quellendaten veraltet | Mehr als 2 geplante Intervalle ohne erfolgreichen Lauf. | Betriebsalarm und sichtbarer Quellenstatus. |
| Dead-Letter-Jobs | Mindestens 1 neuer Eintrag. | Administrator prüft Ursache und Wiederaufnahme. |
| Queue-Rückstand | Ältester Job über konfiguriertem Grenzwert. | Worker-/Datenbankzustand prüfen. |
| Backup fehlt | Kein erfolgreiches Backup im vorgesehenen Fenster. | Betriebsalarm; Demo-Freigabe blockieren. |
| OIDC/DB nicht bereit | Readiness fehlgeschlagen. | Kein Traffic; Ursache beheben. |

### 16.5 Backup und Restore

- Tägliches verschlüsseltes logisches Backup für die private Demo; Aufbewahrung mindestens 14 tägliche Stände.
- Vor Migrationen und Releases mit Schemaänderung wird ein zusätzlicher Wiederherstellungspunkt erzeugt.
- Restore erfolgt in eine leere Instanz und prüft Schema, Objektzahlen, Stichproben-Hashes, offene Signale und Auditketten.
- Mindestens einmal pro Release-Meilenstein wird der Restore praktisch getestet und protokolliert.

---

## 17. Test-, Qualitäts- und Lieferkonzept

Qualität wird als automatisierte Lieferbedingung umgesetzt. Fachliche Kernlogik wird ohne Infrastruktur testbar gehalten; Adapter werden mit Contract- und Integrationstests geprüft. End-to-End-Tests decken die kritischen Benutzer- und Betriebsabläufe ab.

### 17.1 Testpyramide

| Stufe | Gegenstand | Ausführung |
|---|---|---|
| Unit | Wertobjekte, Statusautomat, Matching-Score, Prioritätsregeln, SLA-Uhren und Retention. | Bei jedem Commit; deterministisch und parallel. |
| Property/Fuzz | Parser, Versionen, CSV, URLs, Filter und Zustandsinvarianten. | In CI mit festem Budget; gefundene Fälle werden Regressionstests. |
| Integration | PostgreSQL-Repositories, Migrationen, Jobs, Outbox und OIDC-Validierung. | Mit kurzlebiger realer PostgreSQL-Instanz. |
| Adapter Contract | NVD, KEV, EPSS, Mail, Webhook und später Ticketing. | Gegen versionierte Fixtures; optionale kontrollierte Live-Smoke-Tests. |
| API Contract | OpenAPI-Schema, Statuscodes, Problem Details, Auth und Pagination. | Build blockiert bei Drift. |
| End-to-End | Login, Inventarimport, Quellenlauf, Signal, Triage, SLA, Export und Restore. | Pro Release-Kandidat auf Referenzumgebung. |
| Performance | 250 000 CVEs, 10 000 Assets, Listenabfragen und inkrementeller Lauf; die Anzahl erzeugter Jobs wird gemessen und als Schwellwert festgehalten und darf nicht in der Grössenordnung der CVE-Anzahl liegen. | Vor MVP-Abnahme und bei relevanten Persistenzänderungen. |
| Security | SAST, Dependency-/Image-Scan, Secret-Scan und ausgewählte DAST-Fälle. | Bei Commit/Release gemäss Kostenprofil. |

### 17.2 Testdatenstrategie

- Versionierte synthetische Fixtures bilden P1-P4, high/medium/low/none, alle Statuswechsel und SLA-Zustände ab.
- Externe Payload-Fixtures stammen aus öffentlichen Quellen, werden auf notwendige Felder reduziert und mit Abrufdatum dokumentiert.
- Keine realen internen Assetnamen, Benutzer oder vertraulichen Kommentare gelangen in Repository oder CI.
- Performance-Daten werden deterministisch generiert und besitzen erwartete Objekt- und Treffermengen.
- Zeitabhängige Tests verwenden den Clock-Port; Netzwerkfehler verwenden kontrollierte Fake-Server statt instabiler Live-Abhängigkeit.

### 17.3 CI-Pipeline

1. Formatierung, go vet, statische Analyse, Lizenz- und Secret-Prüfung.
2. Unit-, Fuzz-Budget-, Integrations- und Race-Detection-Tests.
3. OpenAPI-Validierung, erneute Codegenerierung mit Diff gegen den Commit sowie SQL-Query-, Migration- und generierter-Code-Driftprüfung.
4. Build reproduzierbarer Binaries und OCI-Images mit Commit- und Versionsmetadaten.
5. SBOM, Dependency- und Container-Schwachstellenscan.
6. Signierung beziehungsweise Provenance-Vorbereitung für Release-Artefakte.
7. Deployment in private Demo nur aus geschütztem Branch/Tag nach erfolgreichen Gates.

### 17.4 Definition of Done

- Akzeptanzkriterien und Fehlerfälle sind umgesetzt und automatisiert geprüft.
- Berechtigungen, Audit, Metriken und Logs des Anwendungsfalls sind berücksichtigt.
- API- und Benutzerdokumentation sind aktualisiert; Breaking Changes sind ausgeschlossen oder versioniert.
- Migration, Rollback-Auswirkung und Retention wurden geprüft, sofern Datenstrukturen betroffen sind.
- Keine offenen kritischen Sicherheits- oder Qualitätsbefunde.
- Der Anwendungsfall ist mit synthetischen Daten demonstrierbar und auf eine Fachanforderung rückverfolgbar.

---

## 18. Umsetzungsplan und Lieferobjekte

Die Umsetzung erfolgt vertikal: Jede Iteration liefert einen demonstrierbaren Pfad durch API, Fachlogik, Datenbank, Audit und mindestens einen Bedienkanal. Schätzungen werden erst auf Task-Ebene vorgenommen; das Konzept definiert Reihenfolge, Abhängigkeiten und Exit-Kriterien.

### 18.1 Iterationen

| Iteration | Schwerpunkt | Lieferobjekte | Exit-Kriterium |
|---|---|---|---|
| I1a | Skeleton & Gates | Repository gemäss Kap. 3.2, drei lauffähige Binaries, Compose mit PostgreSQL / OIDC-Testanbieter / Mail-Testserver, Migrations-Runner mit Prüfsummen-Log, Health und Readiness, Startvalidierung, CI-Stufen 1–2, Architekturprüfung. | docker compose up bringt alles hoch, /health/ready ist grün, CI bricht bei verbotenem Import ab, eine leere Referenzdatenbank migriert sauber und eine veränderte Migration verhindert den Start. |
| I1b | Walking Skeleton | OpenAPI-Dokument, Codegenerierung + Diff-Gate, Contract-Test, ein Datensatz durch die Kette synthetische Quelle → Rohdaten → Evidenz → Match → Signal, zwei lesende Endpunkte, demo seed, Outbox und Auditereignis atomar für diesen Pfad. | Ein synthetischer Datensatz wird importiert und als lesbares Signal über die API angezeigt; Fehlerinjektion zwischen Fachänderung und Outbox zeigt vollständigen Rollback. |
| I2 | Quellen & Evidenz (Zeitfenster) | NVD-, KEV- und EPSS-Adapter, Rohdaten, Normalisierung, Idempotenz, Quarantäne, Quellenmonitor. Läuft gegen ein begrenztes Zeitfenster, nicht den Gesamtdatenbestand. | Zweifacher Referenzimport ohne Dubletten; Fehlerfall isoliert und erneut verarbeitbar; EPSS-Tagesbestand geladen und Zeilenzahl gemessen. |
| I3 | Inventar & Matching | Asset- und Komponentenmodell, CSV-Preview/Commit, alias_rules, decision_rules, Versionssemantik, Matching und Konfidenz, Inventar-Produktindex und Kandidaten-Vorfilter, matching.rebuild. | Referenzmatrix für alle Assettypen und Match-Stufen bestanden; NVD-Vollimport mit Jobanzahl unter Schwellwert abgeschlossen. |
| I4 | Signale, Priorität & SLA | priority_rules, P1-P4-Regeln, Statusautomat, Owner, Kommentare, SLA-Uhren, Outbox und Benachrichtigung. | P1-P4 inklusive beschleunigtem SLA-Test und Audit nachweisbar. |
| I5a | Identität & Autorisierung | OIDC-Integration, Rollen- und Permission-Matrix inklusive audit.reveal_identity, Autorisierung auf Anwendungsfall-Ebene, lokaler Schutzmodus und Online-Bypass-Sperre. | Rollenmatrix bestanden; API/CLI-Kanalparität nachgewiesen; negativer Starttest mit aktiviertem Bypass. |
| I5b | Web & CLI | Triage-Oberfläche, Administration, vollständige CLI. | API/Web/CLI-Kanalparität bestanden; UX-Leitplanken aus Kap. 11.2 erfüllt. |
| I6 | Betrieb & Abnahme | Exports, Retention inklusive Pseudonymisierungsstufe, Backup/Restore, Observability, Performance, Security-Härtung und private Demo. | Alle Muss-Abnahmefälle bestanden; Betriebs- und Benutzerdokumentation vollständig. |

Die vollständige, verbindliche Iterationstabelle ist in docs/plan/iterations.md geführt.

### 18.2 Lieferobjekte

- Quellcode-Repository mit Go-Modul, Webressourcen, Migrationen, Queries und Buildkonfiguration.
- Versionierter OpenAPI-3.1-Vertrag und maschinenlesbare Beispieldaten.
- OCI-Images für Server und Worker sowie plattformgerechtes CLI-Binary.
- Compose-Umgebung, Demo-Konfiguration und Deployment-Anleitung für die private Online-Demo.
- Synthetischer Referenzdatensatz mit Erwartungsmatrix.
- Automatisierte Testreports, SBOM, Scanberichte und Performance-Nachweis.
- Administrator-, Benutzer-, Betriebs-, Backup/Restore- und Fehlerbehebungsdokumentation.
- Ausgefülltes technisches Abnahmeprotokoll mit Nachweisen und dokumentierten Abweichungen.

### 18.3 Abhängigkeiten

| Abhängigkeit | Benötigt bis | Fallback |
|---|---|---|
| OIDC-Provider und Claims-Mapping | Start I5 | Lokaler Testprovider; Online-Abnahme erst mit Zielprovider. |
| NVD API-Key | I2 | Niedrigere Abrufrate ohne Key; kontrollierte Referenzfixtures. |
| SMTP/Webhook-Ziel | I4 | Lokaler Mail-Testserver und signierter Fake-Webhook. |
| Private Demo-Infrastruktur | Start I6 | Lokale Compose-Abnahme; Online-Freigabe separat. |
| Ticketing-Zielsystem | Nach MVP | Port und Contract-Fixtures ohne produktiven Adapter. |
| Inventar-Produktindex und Normalisierungsregeln | I3 | I2 bleibt auf ein reduziertes Zeitfenster beschränkt. |

---

## 19. Technische Abnahme und Rückverfolgbarkeit

Die technische Abnahme ergänzt die fachlichen Testfälle AT-001 bis AT-021. Ein technischer Test gilt als bestanden, wenn Vorgehen, erwartetes Ergebnis, tatsächliches Ergebnis und maschinenlesbarer oder visueller Nachweis dokumentiert sind.

### 19.1 Technische Anforderungen

| ID | Technische Vorgabe | Prüfbarer Nachweis |
|---|---|---|
| TR-001 | Domänenmodule importieren keine HTTP-, Datenbank-, OIDC- oder UI-Adapter. | Automatisierte Architekturprüfung und Code-Review. |
| TR-002 | Server, Worker und CLI werden aus demselben Go-Modul reproduzierbar gebaut. | Clean Build erzeugt alle drei Artefakte. |
| TR-003 | OpenAPI 3.1 ist der versionierte API-Vertrag und driftet nicht von der Implementierung. | Contract-Test und Schema-Validierung erfolgreich. |
| TR-004 | Jede fachliche Änderung speichert Zustand, Audit und Outbox atomar. | Rollback-/Fehlerinjektion zeigt keine Teilzustände. |
| TR-005 | Quellenimporte sind cursorbasiert, idempotent und einzeln fehlertolerant. | Doppelimport und Misch-Feed bestehen. |
| TR-006 | EPSS-Bulkimport verwendet den täglichen Datensatz statt Einzelabfragen pro CVE. | Adapter- und Lasttest dokumentiert. |
| TR-007 | Matching speichert Methode, Score, Konfidenz, Gründe und Regelversion. | Referenzmatrix vollständig nachvollziehbar. |
| TR-008 | Priorität ist deterministisch und speichert alle Faktoren sowie die Regelversion. | Gleicher Input ergibt kanal- und laufunabhängig dasselbe Resultat. |
| TR-009 | SLA- und Retention-Logik nutzt eine injizierbare Uhr. | Beschleunigte und simulierte Zeitprüfungen ohne Sleep. |
| TR-010 | Online-Betrieb verweigert lokalen Authentisierungs-Bypass. | Negativer Starttest erfolgreich. |
| TR-011 | Autorisierung erfolgt im Anwendungsfall und gilt für API, Web und CLI gleich. | Rollenmatrix und Kanalparität bestanden. |
| TR-012 | Jobs verwenden Lease, begrenzte Retries, Dead-Letter und Deduplizierung. | Crash-/Retry-Test ohne doppelte Fachwirkung. |
| TR-013 | Logs enthalten keine Secrets, Tokens oder unkontrollierte Payloads. | Automatisierte Redaction- und Log-Prüfung. |
| TR-014 | Migrationen sind versioniert, geprüft und exklusiv ausführbar. | Leere und bestehende Referenzdatenbank migrieren erfolgreich. |
| TR-015 | Backup und Restore stellen Fachzustand und Audit nachweisbar wieder her. | Restore-Test und Hash-/Objektvergleich bestanden. |
| TR-016 | Ticketing-Port, Linkmodell und idempotente Sync-Ereignisse sind im MVP vorbereitet. | Contract-Test mit Fake-Adapter; kein produktiver Adapter erforderlich. |
| TR-017 | Generierter API-Code ist reproduzierbar und driftet nicht vom Schema. | Codegenerierungs-Diff-Gate in CI schlägt bei manueller Änderung an. |
| TR-018 | Angewendete Migrationen sind gegen nachträgliche Änderung geschützt. | Negativer Test: eine veränderte Migration verhindert den Start. |
| TR-019 | Bulk-Importe erzeugen keine Jobs in der Grössenordnung der Quelldatensätze. | Lasttest zählt erzeugte Jobs gegen einen definierten Schwellwert. |
| TR-020 | Audit-Identitätsauflösung ist berechtigungsgesteuert und selbst-auditiert. | Positiv-/Negativtest je Rolle; erzeugtes Auditereignis geprüft. |

### 19.2 Technische Abnahmematrix

| ID | Prüfung | Vorgehen | Erwartetes Ergebnis | Bezug |
|---|---|---|---|---|
| TAT-01 | Clean Build | Leeres Build-Environment; alle Binaries und Images bauen. | Reproduzierbare Artefakte mit Version und SBOM. | TR-002 |
| TAT-02 | Architekturgrenzen | Abhängigkeitsregeln automatisiert prüfen. | Keine verbotenen Imports in Domain/Application. | TR-001 |
| TAT-03 | API Contract | OpenAPI validieren und Contract-Suite ausführen. | Schema, Statuscodes und Fehlerformat stimmen. | TR-003 |
| TAT-04 | Atomicity | Fehler zwischen Fachänderung und Outbox injizieren. | Vollständiger Commit oder vollständiger Rollback. | TR-004 |
| TAT-05 | Worker Crash | Job nach Reservierung abbrechen und Worker neu starten. | Lease läuft ab; Job ohne doppelte Wirkung fortgesetzt. | TR-012 |
| TAT-06 | OIDC negativ | Falscher Issuer, Audience, Signatur und abgelaufenes Token. | Alle Varianten werden sicher abgewiesen. | TR-010-011 |
| TAT-07 | SSRF | Quelle auf Loopback, Link-Local und privates Netz konfigurieren. | Nicht freigegebene Ziele werden blockiert und auditiert. | TR-013 |
| TAT-08 | SLA-Uhr | P1-P4 mit Fake Clock durch Fristen und Pause führen. | Deadlines, Eskalation und Audit exakt reproduzierbar. | TR-009 |
| TAT-09 | Retention | Objekte vor/nach Frist, Legal Hold und Wiedereröffnung. | Nur freigegebene abgelaufene Daten werden entfernt. | TR-009 |
| TAT-10 | Migration | Leeres Schema und vorherigen Release-Stand migrieren. | Schema korrekt; keine unerwarteten Datenverluste. | TR-014 |
| TAT-11 | Restore | Backup in neue Instanz einspielen und vergleichen. | Signale, Status, Audit und Referenz-Hashes stimmen. | TR-015 |
| TAT-12 | Ticket Contract | Fake-Adapter mit Duplikat, Timeout und Konflikt ausführen. | Keine Schleife/stille Überschreibung; Retry und Hinweis korrekt. | TR-016 |
| TAT-13 | Codegen-Drift | Generierten Handler von Hand editieren, CI ausführen. | Build bricht ab. | TR-017 |
| TAT-14 | Migrations-Prüfsumme | Eine angewendete Migrationsdatei verändern, Start versuchen. | Start bricht mit klarer Meldung ab. | TR-018 |
| TAT-15 | Bulk-Job-Kardinalität | Referenz-Vollimport ausführen, erzeugte Jobs zählen. | Jobanzahl unter Schwellwert; matching.rebuild statt einzelner Jobs. | TR-019 |
| TAT-16 | Identitätsauflösung | Auflösung je Rolle versuchen; erfolgreiche Auflösung prüfen. | Nur berechtigte Rollen; Auditereignis mit Begründung vorhanden. | TR-020 |

### 19.3 Rückverfolgbarkeit zum Fachkonzept

| Fachbereich | Fachanforderungen | Umsetzungskapitel | Technischer Nachweis |
|---|---|---|---|
| Quellen | FR-001-005, FR-008-010, FR-020-021, FR-024 | 5, 7, 8, 14 | AT-002-003, AT-011-012; TAT-04-05 |
| Inventar/Matching | FR-006-007, FR-011-012, FR-030 | 6-9 | AT-004-005, AT-007, AT-019 |
| Priorität/Workflow | FR-013-018, FR-031-032 | 9-11, 14 | AT-006-010, AT-020; TAT-08 |
| API/Web/CLI | FR-017-018, FR-022, FR-025-027 | 10-11 | AT-010, AT-014, AT-016-017; TAT-03 |
| Identity/Security | FR-028-029; NFR-006-007, NFR-014 | 12 | AT-018; TAT-06-07 |
| Audit/Retention | FR-019, FR-033; NFR-005, NFR-015 | 7, 13 | AT-009, AT-021; TAT-09, TAT-16 |
| Betrieb/Qualität | NFR-001-004, NFR-008-013 | 4, 16-18 | AT-001, AT-013, AT-015; TAT-01-02, TAT-10-11, TAT-13-15 |
| Ticketing später | FR-034 | 15 | TAT-12 |

---

## 20. Risiken, Annahmen und offene Detailentscheide

### 20.1 Technische Risiken

| ID | Risiko | Auswirkung | Gegenmassnahme |
|---|---|---|---|
| TRI-01 | NVD-Volumen und Rate-Limits verlängern Initialimport. | Verzögerte Demo oder unvollständiger Referenzstand. | Checkpointing, API-Key, Caching, Fixtures und separater Initialimport. |
| TRI-02 | Produkt- und Versionssemantik unterscheidet sich stark. | Fehlzuordnungen oder geringe Konfidenz. | Adapterbare VersionStrategy, kontrollierte Aliasse, Referenzmatrix und menschliche Prüfung. |
| TRI-03 | OIDC-Provider unterstützt Device Flow oder gewünschte Claims nicht. | CLI-Anmeldung oder Rollenmapping muss angepasst werden. | Capability-Prüfung vor I5; Loopback-Flow und internes Mapping als Fallback. |
| TRI-04 | PostgreSQL-Jobqueue wird bei hohem Volumen zum Engpass. | Verzögerte Verarbeitung. | Queue-Metriken, SKIP LOCKED, kurze Transaktionen, Kandidaten-Vorfilter, Batch-Payload, matching.rebuild und Dedupe-Fenster bis Abschluss (ADR-012); Broker erst bei gemessenem Bedarf. |
| TRI-05 | Fünfjährige Aufbewahrung erhöht Datenmenge. | Backup-, Restore- und Abfragezeiten steigen. | Partitionierung, Archivierungsprüfung, Kapazitätsmetriken und regelmässige Restore-Tests. |
| TRI-06 | Serverseitige Weboberfläche erreicht bei komplexer Interaktion Grenzen. | Spätere UI-Erweiterungen werden aufwendiger. | Klare API, progressive Komponenten und optionaler separater Frontend-Client ohne Domänenänderung. |
| TRI-07 | Ticket-Statusmodelle sind nicht verlustfrei abbildbar. | Konflikte oder falsche Abschlüsse. | Versioniertes Mapping, führende Systeme, Konfliktqueue und keine stille Überschreibung. |

### 20.2 Arbeitsannahmen

- Das MVP ist eine Einzelmandantenlösung und verarbeitet synthetische oder ausdrücklich freigegebene Inventardaten.
- Eine PostgreSQL-Instanz reicht für das Referenzvolumen und die private Online-Demo aus.
- Die Benutzerzahl ist klein; fachliche Last entsteht primär durch Quellen- und Matching-Verarbeitung.
- Externe Primärquellen dürfen entsprechend ihren Nutzungsbedingungen abgerufen und für den beschriebenen Zweck verarbeitet werden.
- Der professionelle 24/7-Prozess wird technisch abgebildet; die tatsächliche personelle Besetzung liegt ausserhalb des Systems.
- Produktive Geheimhaltungs-, Datenschutz- und Infrastrukturklassifikation wird vor einem echten Betrieb separat durchgeführt.

### 20.3 Offene Detailentscheide

| ID | Entscheidbedarf | Spätester Termin | Vorgeschlagener Default |
|---|---|---|---|
| TD-01 | Konkreter OIDC-Provider und Claims-/Rollenmapping. | Vor I5 | Providerneutral entwickeln; lokaler Testprovider für CI. |
| TD-02 | HTTP-Router, SQL-Codegenerator und Migrationswerkzeug. | I1 | Geschlossen durch ADR-008 bis ADR-011. |
| TD-03 | Konkrete progressive Webbibliothek und CSS-Toolchain. | I1/I5 | Serverseitige Templates, minimale JavaScript-Abhängigkeit. |
| TD-04 | Zustellkanal der privaten Demo. | Vor I4 | In-App plus SMTP-Test/SMTP; Webhook optional. |
| TD-05 | BACS/NCSC-Bezugsweg und Intervall. | Nach MVP | Strukturierter offizieller Feed; sonst kontrollierter manueller Import. |
| TD-06 | Ticketing-Ziel, Mapping und automatische P1/P2-Erstellung. | Nach MVP | Keine automatische Erstellung; Contract mit Fake-Adapter. |
| TD-07 | Zielvorgaben für RPO/RTO der privaten Demo. | Vor I6 | RPO 24 h, RTO 4 h als vorläufige Planungswerte. |
| TD-08 | Rechtsgrundlage und Frist für personenbezogene Daten in Auditaufzeichnungen. Da die Pseudonymisierung reversibel ist, muss die Grundlage die gesamte Aufbewahrungsfrist abdecken. | Vor I6 | Pseudonymisierung 12 Monate nach Ausscheiden der Person oder nach closed_at, je nachdem was später liegt. |

---

## 21. Referenzen

### 21.1 Bezugsdokumente

- RiskSignal Fachkonzept v0.2, 8. September 2026.
- Fachliche Anforderungen FR-001 bis FR-034, nichtfunktionale Anforderungen NFR-001 bis NFR-015 und Abnahmematrix AT-001 bis AT-021.

### 21.2 Technische Primärquellen

- Go - Organizing a Go module: https://go.dev/doc/modules/layout
- Go - Managing dependencies: https://go.dev/doc/modules/managing-dependencies
- OpenAPI Specification: https://spec.openapis.org/oas/latest.html
- OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
- OAuth 2.0 Security Best Current Practice, RFC 9700: https://www.rfc-editor.org/rfc/rfc9700.html
- Problem Details for HTTP APIs, RFC 9457: https://www.rfc-editor.org/rfc/rfc9457.html
- PostgreSQL Documentation: https://www.postgresql.org/docs/current/
- NVD Vulnerability API: https://nvd.nist.gov/developers/vulnerabilities
- NVD API Workflows: https://nvd.nist.gov/developers/api-workflows
- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- FIRST EPSS - Tagesdateien: https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz
- FIRST EPSS API: https://api.first.org/epss/ (für Einzelabfragen)
- Bundesamt für Cybersicherheit BACS: https://www.bacs.admin.ch/
- OWASP Application Security Verification Standard: https://owasp.org/www-project-application-security-verification-standard/
- OpenTelemetry Specification: https://opentelemetry.io/docs/specs/

### 21.3 Änderungshistorie

| Version | Datum | Änderung | Status |
|---|---|---|---|
| 0.1 | 08.09.2026 | Erstfassung auf Basis des RiskSignal Fachkonzepts v0.2. | Entwurf |
| 0.2 | 08.09.2026 | Übernahme der sieben Review-Befunde; ADR-008 bis ADR-015; TD-02 geschlossen, TD-08 ergänzt; I1 geteilt. | Entwurf |

---

## Anhang A — Architekturentscheide ADR-008 bis ADR-015

Die acht in der Review vom 8. September 2026 getroffenen Architekturentscheide sind
nachfolgend im vollen Wortlaut wiedergegeben, damit das Umsetzungskonzept ohne
Begleitdokument umsetzbar ist. Die Entscheide liegen original in englischer Sprache
(Projektsprache) in docs/adr/ vor; die deutschen Kurzfassungen stehen in Kapitel 1.2.
Massgeblich ist der Wortlaut der Entscheide selbst.


---

# ADR-008 — HTTP routing on net/http, Go 1.27

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 3.1, 10.2; closes TD-02 (part 1) |

## Context

Chapter 3.1 requires "Go net/http with a lightweight router" but names no concrete
tool. TD-02 carried that decision with a due date of I1 — which was circular,
because I1 cannot start without it.

The concept likewise fixed no Go version, saying only "a supported stable Go
version".

## Decision

1. Routing on the standard library `net/http` using `http.ServeMux`. No router
   framework.
2. Middleware chaining as a small in-repository building block.
3. The toolchain is pinned to **Go 1.27** (`go.mod`, container image, CI).

## Rationale

Since Go 1.22, `ServeMux` supports method- and pattern-based routing of the form
`GET /api/v1/signals/{id}`. That covers the complete endpoint list in chapter 10.2.
An additional dependency at the centre of every HTTP request would add no
functional value and would conflict with chapter 3's instruction to keep
dependencies deliberately narrow.

Middleware chaining is a few dozen lines and therefore stays entirely under our own
control — which matters for the security requirements in chapter 12.3 (CSRF, CORS,
security headers, correlation ID).

On the Go version: currently supported are 1.27 (released 2026-08-19) and 1.26
(released 2026-02-10); 1.25 went out of support in August 2026. Go 1.26 loses
support when 1.28 ships (expected February 2027), which falls in the middle of
implementation. 1.27 is also a prerequisite for ADR-011 — oapi-codegen requires at
least Go 1.24 for the `net/http` target.

## Consequences

- A middleware building block must be written and tested in I1a.
- No sub-router convenience; endpoint groups are formed by path prefix and explicit
  registration. Uncritical at the size given in chapter 10.2.
- The Go version is part of build reproducibility (TR-002) and is kept identical
  across `go.mod`, containerfile and CI.

## Alternatives rejected

- **chi** — clean and slim, but the gain is limited to sub-routers and prebuilt
  middleware. Not enough to justify a central dependency.
- **gin / echo** — bring their own context and binding models, which compete with
  the generated types from ADR-011 and the port structure in chapter 2.3.

---

# ADR-009 — Data access via sqlc and pgx/v5

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 3.1, 7, 17.3; closes TD-02 (part 2) |

## Context

Chapter 3.1 requires "access via pgx and generated, typed SQL queries", and chapter
17.3 lists an "SQL query drift check" as a CI stage. That names the pattern but no
tool.

## Decision

Queries live as SQL files under `/db/queries` and are compiled into typed Go code by
**sqlc**. The driver is **pgx/v5** directly, without `database/sql`.

Generated code is committed. CI regenerates and fails on any diff against the commit.

## Rationale

SQL stays visible and reviewable — important for the queries in chapter 7.1, which
depend on indexes, partial uniqueness and `SKIP LOCKED`. An ORM would obscure
exactly those places.

Typing catches schema divergence at compile time rather than at runtime. Together
with the drift gate this produces the same mechanic as ADR-011: a divergence becomes
a build failure, not a test finding.

pgx/v5 without the `database/sql` layer gives access to `COPY` (ADR-013), batching
and the native PostgreSQL types needed for `JSONB` raw data and `timestamptz`.

## Consequences

- `sqlc.yaml` and the generation step are part of the build and of CI.
- Migrations (ADR-010) are authoritative for the schema; sqlc reads them to derive
  types. Build order: write the migration, then generate.
- The dynamic filters in chapter 10.4 (signal filter with many optional fields)
  cannot be fully generated. For those queries a clearly bounded, parameterised
  builder is permitted — never string concatenation with user input.

## Alternatives rejected

- **GORM / ent** — obscure the persistence details that chapter 7 depends on.
- **sqlx** — does not provide the typing, so drift protection would stay manual.

---

# ADR-010 — Migrations with goose and an own checksum log

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 4.4, 7.4; TR-014, TAT-10; closes TD-02 (part 3) |

## Context

Chapter 7.4 requires numbered, immutable, forward-only SQL migrations. Chapter 4.4
additionally requires that migrations run once under an exclusive lock, before
application start, and are "recorded with a checksum".

## Decision

1. **goose** as the migration tool, embedded as a library in the binaries.
2. Migrations are plain SQL under `/db/migrations`, embedded via `embed.FS`.
3. Execution only through `risksignal maintenance migrate`, with a mandatory dry run
   as required by chapter 11.3.
4. **An own checksum log** in a table `schema_migration_log`: per applied migration
   the version, a hash of the file content, timestamp and duration. Before every
   run, the hashes of already-applied migrations are verified against the files
   embedded in the binary; any divergence aborts.

## Rationale

goose matches the required model: numbered SQL files, forward-only, PostgreSQL
advisory lock, embeddable as a library. The migration therefore ships inside the
same immutable artefact as the application (TR-002) and no second tool enters the
deployment.

Point 4 is our own code because no widely used Go migration tool provides this in
the form chapter 4.4 intends. The effort is small and the benefit concrete: a
retroactively altered, already-applied migration is detected instead of silently
diverging. That is the technical counterpart of "immutable" in chapter 7.4.

## Consequences

- A dedicated I1a work package for the checksum log, including a negative test
  (an altered migration must prevent startup).
- `schema_migration_log` is itself part of the schema and is created by the first
  migration.
- Expand-migrate-contract (chapter 7.4) remains manual across several numbered
  steps — deliberately, so destructive steps are approved individually.

## Alternatives rejected

- **golang-migrate** — functionally close, but library embedding and error semantics
  are less straightforward.
- **Atlas** — powerful, but its declarative model (target schema, generated
  transition) conflicts with "numbered, immutable migration" and with a manually
  driven expand-migrate-contract.

---

# ADR-011 — Generated server interfaces from OpenAPI (mandatory)

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 3.1, 10, 17.3; TR-003, TAT-03; extends TD-02 |

## Context

Chapter 3.1 listed generated clients and server types as **optional**. TR-003, by
contrast, requires that the OpenAPI contract does not drift from the implementation.
With hand-written handler types the contract test is the only safety net — and it
only checks what it checks. Untested fields drift silently.

## Decision

Code generation becomes **mandatory**. Tool: **oapi-codegen v2**, target `net/http`
(matching ADR-008).

Generated:

- request and response types, parameter structs
- the `ServerInterface` that handlers implement
- route registration
- request validation against the schema
- optionally the Go client, used for E2E tests and the CLI adapter

Not generated: the mapping between generated type and domain object. Generated types
are adapter types and must not appear in `internal/domain`.

## Rationale

A generated server interface turns contract drift into a **compile error** rather
than a test finding. A newly declared endpoint that nobody implements stops the
project from building.

oapi-codegen supports OpenAPI 3.1 including the 3.1 idioms (`type: [T, "null"]`,
enums via `oneOf` + `const`), and its `net/http` target requires Go 1.24 or newer —
satisfied by ADR-008 (Go 1.27).

## Consequences

Three CI gates instead of one:

1. validate the OpenAPI document against the 3.1 specification
2. re-run code generation, diff the result against the commit, fail on divergence
3. contract test against the running server (status codes, problem details, auth,
   pagination)

Gate 2 is the actual gain over v0.1.

Two things move out of prose and into the schema:

- RFC 9457 problem details as a reusable response component (chapter 10.1)
- `Idempotency-Key` and `If-Match` as declared header parameters

The architecture check in TR-001 must add the generated package path to the list of
imports forbidden in `internal/domain`.

## Alternatives rejected

- **Hand-written handler types with contract tests** — the v0.1 status quo; satisfies
  TR-003 only as far as the tests reach.
- **Code-first with a generated OpenAPI document** — contradicts "schema-first" in
  chapter 3.1 and makes the contract a by-product of the implementation.

---

# ADR-012 — Bulk matching is inventory-driven, not CVE-driven

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 8.1, 9, 14.1, 17.1; TRI-04 |

## Context

Chapter 8.1 step 7 has the right instinct — "no global recomputation without cause".
Chapter 14.1, however, sets the idempotency key of `matching.recompute` to
`vulnerability_id + component_scope + rule_version`, i.e. one job per CVE. On first
import every CVE is new; at a scale of several hundred thousand published CVEs, an
equivalent number of jobs would be created.

The performance test in chapter 17.1 (250,000 CVEs, 10,000 assets) targets exactly
this case, but the concept does not say how it is meant to pass. TRI-04 names only
generic countermeasures.

## Decision

1. **Candidate pre-filter before job creation.** An index over the normalised
   `vendor`/`product` of components. After normalisation, a semi-join decides which
   vulnerabilities have any candidate in the inventory at all. Only those create jobs.
2. **New job type `matching.rebuild`.** Initial import and rule-version changes create
   exactly one job that walks the components inventory-driven in bounded batches.
   Idempotency key: `rule_version + inventory_snapshot`.
3. **Batch payload for `matching.recompute`.** A capped list (guide value 500) instead
   of one vulnerability per job. Idempotency key: hash over the sorted ID list plus
   `rule_version`.
4. **Dedupe window until completion.** The `unique(dedupe_key)` from chapter 7.1 stays
   in effect while a job runs — not only until it is claimed.

## Rationale

In bulk, the favourable direction inverts: 10,000 assets with a few hundred distinct
normalised products are two orders of magnitude fewer than the total CVE population.
Point 1 reduces job creation in incremental operation, point 2 avoids it entirely in
bulk, point 3 cuts queue row count, and point 4 prevents double enqueueing when
source runs overlap.

## Consequences

- The product index on `components` and the normalisation rules in chapter 9.1 are
  prerequisites. They belong to I3.
- For the plan this means: **I2 runs against a time window, not the full data set.
  The NVD full import becomes the exit criterion of I3.**
- The same pre-filter feeds `epss_history` (ADR-013). Build once, use twice.
- Chapter 14.1 gains `matching.rebuild`; chapter 8.1 step 7 is made precise; the
  TRI-04 countermeasure is extended with pre-filter and batching.

---

# ADR-013 — Bulk file sources: one raw record per file, full sets replaced by TRUNCATE

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 7.1, 8.1, 8.3, 8.4, 13.3, 21.2 |

## Context

Chapter 8.1 step 4 requires storing and hashing raw content unchanged; `raw_records`
carries `unique(source_id, external_id, content_hash)`. For the daily EPSS full set it
was left open what constitutes a raw record. If `external_id` were the CVE ID, the
table would grow by several hundred thousand rows **per day** — at 180 days retention
(chapter 13.3), tens of millions of rows for a source that supplies three numbers per
CVE.

Also open: how the full set is replaced daily without causing table and index bloat.

Additionally, chapter 21.2 points at a source path for the EPSS daily files that is no
longer current.

## Decision

1. **For bulk file sources, a `raw_record` is the file, not the row.** `external_id`
   is the file name or date, the payload is the compressed file, plus a hash. Rows are
   streamed during parsing straight into the normalised tables. This applies to EPSS
   and to the KEV catalogue (chapter 8.3 already describes it that way) and is stated
   generally in chapter 8.1 rather than per adapter.
2. **Two tables for EPSS:**
   - `epss_current` — daily state of all scored CVEs, replaced by `TRUNCATE` + `COPY`
     within **one** transaction
   - `epss_history` — only CVEs with inventory relevance, append-only, fed from the
     same run via the candidate pre-filter from ADR-012
3. **No foreign keys onto `epss_current`.** Prioritisation reads by `cve_id` lookup.
4. **Corrected download URL:** the EPSS daily files are published at
   `https://epss.empiricalsecurity.com/epss_scores-YYYY-mm-dd.csv.gz`. The EPSS API at
   `api.first.org` remains as described in chapter 8.4 for targeted single lookups and
   diagnostics.

## Rationale

On 1: for a bulk file the evidential value of the raw record lies in the file as a
whole — provenance, fetch time, hash. A per-CVE row copy multiplies data volume
without improving traceability.

On 2: `TRUNCATE` reclaims space immediately and creates no dead tuples. A daily
`DELETE`+`INSERT` over the full set produces bloat that autovacuum can barely keep up
with. In PostgreSQL `TRUNCATE` is transactional, so the swap is atomic.

## Consequences

- `TRUNCATE` takes an ACCESS EXCLUSIVE lock; reads on `epss_current` block for the
  duration of the load. Acceptable given the small user count (chapter 20.2) and a
  load time of seconds — the decision is deliberate and belongs in the operations
  handbook.
- Should the lock window later become a problem, the way out is a partitioned table
  with `ATTACH`/`DETACH PARTITION`. Not to be anticipated in the MVP.
- The actual row count of the daily set is measured once in I2 and recorded in the
  performance evidence, rather than fixed in the concept.
- Chapter 7.1 gains `epss_current` and `epss_history`; chapter 8.1 the general
  statement on bulk file sources; chapter 8.4 the loading strategy and lock window;
  chapter 21.2 the URL.

---

# ADR-014 — Identity in the audit trail: deactivate, never delete; reversible pseudonymisation

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 12, 12.2, 13.1–13.5; TD-08 |

## Context

Chapter 13.1 stores `actor_id`, `actor_display_name`, `reason` and `before`/`after`
excerpts; chapter 13.3 keeps audit data for five years from `closed_at`. That is
personal data about employees over a long period. Chapter 13.5 governs data
minimisation at write time, but there is no procedure that reduces the personal
reference over time. Chapter 13.4 knows only dry run, hold and deletion — and for
audit data deletion is the wrong answer, because the record is meant to survive.

## Decision

1. **Users are deactivated, never deleted.** Their ID stays permanently referenceable.
   (Principle; chapter 12 gains the corresponding sentence, mirroring the deactivated
   assets in chapter 6.1.)
2. **Pseudonymisation as its own retention stage** between retention and deletion, to
   be added to chapter 13.4:

   | Field | After personal-data period | After 5 years |
   |---|---|---|
   | `actor_id` | retained | deleted with the event |
   | `actor_display_name` | cleared, displayed as `User #<short-id>` | — |
   | `reason`, comments, free text | pseudonymised or removed | — |
   | action, time, target, rule version | retained | deleted with the event |

3. **Pseudonymisation is reversible.** Resolution runs `actor_id` → `users`. No crypto
   mechanism, no key management — the deactivated user record is the key.
4. **Resolution is controlled:**
   - a dedicated permission `audit.reveal_identity`, **not** part of `audit.read`;
     role matrix in chapter 12.2: auditor and product owner yes, admin no
   - every resolution itself emits an audit event `audit.identity_revealed` carrying
     actor, target, time and a mandatory reason
   - resolution is an explicit call via its own endpoint and its own CLI command,
     never a side effect of rendering a list view
5. Two new maintenance commands under `risksignal maintenance`: find all events for a
   person (subject access request) and pseudonymise — both with a dry run per
   chapter 11.3.

## Rationale

The audit trail stays complete and linkable; the question "who decided what, when"
remains answerable internally for as long as the user record exists. The default view
no longer shows a name.

The only loss compared to the denormalisation in chapter 13.1 is the name *as of the
event*: after a name change, resolution returns the current name. Uncritical for audit
purposes, since the identity is the same.

Free text is the larger risk, not the name. `reason` and comments may contain personal
data of third parties that nobody anticipated; they are therefore treated as their own
data category with their own period, not implicitly as "audit".

## Important limitation

**Reversible pseudonymisation is not anonymisation.** As long as the identity can be
resolved, the audit data remains personal data for the full five years. Protection
rests solely on access control, not on a period after which nobody is identifiable
any more. The legal basis must therefore cover the entire retention period. TD-08 is
worded accordingly.

An unlogged resolution would be worse than no pseudonymisation at all, because it
would feign protection — hence point 4 in full or not at all.

## Regulatory frame

xpera is based in Switzerland; the governing law is the revised Federal Act on Data
Protection (revDSG, in force since 1 September 2023), plus the GDPR where there is an
EU nexus. This is not legal advice; period and legal basis are a business and legal
decision (TD-08). Not blocking for an MVP on synthetic data — blocking before real
operation, see chapter 20.2. Fields and the retention stage are built now so that the
later decision does not force a migration.

---

# ADR-015 — Matching is method-led, the score is derived

| Field | Value |
|---|---|
| Status | Accepted |
| Date | 2026-09-08 |
| Relates to | Implementation concept ch. 7.1, 9.1–9.3; TR-007, TR-008 |

## Context

Chapter 9.2 defines a score scale (100 / 95 / 90 / 80 / 65 / 55 / 1–54 / 0) with an
associated method and confidence. The prioritisation rules in chapter 9.3, however,
read confidence only — the score appears in no rule. Operationally there is no
difference between 95 and 90; both are `high`.

The numbers therefore suggest a precision that does not exist, and a new method forces
an arbitrary value between two existing ones.

Exception: `1–54 Candidate` is a *range*. There a similarity really is computed. That
is the only place where the score carries genuine information.

## Decision

| Field | Role |
|---|---|
| `method` | **authoritative**, named enum: `exact_identifier`, `container_digest`, `alias_exact_version`, `canonical_product_range`, `product_uncertain_version`, `controlled_alias_only`, `candidate`, `no_match` |
| `confidence` | enum, derived from `method` through a versioned mapping — this is what the rules read |
| `score` | for deterministic methods a fixed sort rank derived from the method; **only** for `candidate` an actually computed similarity measure |

A new method is therefore a new enum value plus two mappings — no argument about
numbers.

## Also: three missing rule tables

Chapter 7.1 lists none of the tables that chapter 9 presupposes. They are added:

- **`decision_rules`** — manual match corrections and exclusion rules from chapter 9.2,
  with reason, scope of validity, author and expiry. They must survive an automatic
  recomputation; without their own table that is precisely what cannot happen.
- **`alias_rules`** — versioned vendor and product aliases from chapter 9.1.
- **`priority_rules`** — versioned rule configuration with a stable rule ID from
  chapter 9.3.

All three are versioned and auditable; all three are referenced by
`matches.rule_version` and `risk_signals.version` respectively. Without them "rule
version" is a field with no counterpart.

## Consequences

- TR-007 and TR-008 remain fully satisfied: method, score, confidence, reasons and rule
  version are still stored.
- `unique(vulnerability_id, component_id, rule_version)` on `matches` stays valid.
- `alias_rules` and `decision_rules` belong to I3, `priority_rules` to I4.
- The alias rules are a prerequisite for the candidate pre-filter in ADR-012 — without
  normalisation there is no usable product index.
