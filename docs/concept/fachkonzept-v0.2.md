# FACHKONZEPT RiskSignal

**Security Intelligence & Risk Correlation Platform**

| **Merkmal**    | **Angabe**                                       |
|----------------|--------------------------------------------------|
| Dokumentstatus | Entwurf – Grundsatzentscheide eingearbeitet      |
| Version        | 0.2                                              |
| Datum          | 8. September 2026                               |
| Projektphase   | Konzeption; Produkt befindet sich in Entwicklung |
| Verantwortlich | Bruno Schriber / xpera GmbH                      |

> **Transparenzhinweis:** RiskSignal befindet sich zum Zeitpunkt dieser Fassung in der Konzeptions- und Entwicklungsphase. Beschriebene Funktionen sind Soll-Anforderungen und dürfen erst nach erfolgreicher Umsetzung und Abnahme als realisiert bezeichnet werden.

## Dokumentzweck

Dieses Fachkonzept beschreibt Zielbild, fachlichen Umfang, Informationsquellen, Verarbeitungslogik, Sicherheitsgrenzen und Qualitätsanforderungen von RiskSignal. Version 0.2 enthält die getroffenen Grundsatzentscheide zu Bedienung, Zugriff, Inventar, Quellenausbau, Reaktionszeiten, Aufbewahrung und Ticketing. Die nummerierten Anforderungen bilden die verbindliche Grundlage für die anschliessende Umsetzungsplanung. Die Abnahmematrix kann nach der Implementierung direkt zu einem projektspezifischen Abnahmeprotokoll erweitert werden.

## Inhaltsübersicht

- 1. Ausgangslage und Zielbild
- 2. Geltungsbereich und Abgrenzung
- 3. Stakeholder, Rollen und Verantwortlichkeiten
- 4. Informationsquellen
- 5. Fachlicher Gesamtprozess
- 6. Priorisierung und Nachvollziehbarkeit
- 7. Informationsmodell
- 8. Benutzererlebnis und Anwendungsfälle
- 9. Funktionale Anforderungen
- 10. Nichtfunktionale Anforderungen
- 11. Datenschutz, Sicherheit und ethische Leitplanken
- 12. Betriebs- und Fehlerkonzept
- 13. MVP, Ausbaustufen und Umsetzungsstruktur
- 14. Abnahmekonzept und Abnahmematrix
- 15. Annahmen, getroffene Entscheide und Risiken
- 16. Glossar und Referenzen
---

## 1. Ausgangslage und Zielbild

Sicherheitsinformationen stehen in grosser Menge und über zahlreiche Quellen verteilt zur Verfügung. Schwachstellendatenbanken, Behördenkataloge, Herstellerhinweise und interne Systeminventare verwenden unterschiedliche Formate und liefern jeweils nur einen Teil des für eine Entscheidung notwendigen Kontexts. Für kleine und mittlere Organisationen entsteht dadurch erheblicher manueller Aufwand: Meldungen müssen gefunden, zusammengeführt, auf die eigene Umgebung bezogen und priorisiert werden.

RiskSignal soll diese Lücke schliessen. Die Plattform führt ausschliesslich autorisierte interne Inventardaten und öffentlich verfügbare Sicherheitsinformationen zusammen. Sie erzeugt daraus nachvollziehbare, priorisierte Risikosignale für Security- und IT-Operations-Teams. RiskSignal trifft keine autonomen Sicherheitsentscheidungen und führt keine Eingriffe an Zielsystemen aus.

### 1.1 Produktvision

| **Vision:** Aus verteilten öffentlichen Sicherheitsinformationen werden nachvollziehbare und handlungsorientierte Hinweise für die tatsächlich eingesetzte IT-Umgebung. |
|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

### 1.2 Ziele

- Relevante Schwachstellen und Sicherheitswarnungen schneller identifizieren.

- Doppelte oder widersprüchliche Meldungen quellenübergreifend zusammenführen.

- Den Bezug zwischen einer Meldung und dem eigenen Systeminventar transparent herstellen.

- Prioritäten anhand bestätigter Fakten, Nutzungskontext und Unsicherheit erklären.

- Analystinnen und Analysten bei der Triage unterstützen, ohne deren Entscheidung zu ersetzen.

- Alle Bewertungen, Statusänderungen und Quellenstände revisionsnah nachvollziehbar protokollieren.

- Ein real nutzbares Produkt und zugleich ein professionelles Go-Referenzprojekt schaffen.

### 1.3 Erfolgsbild

Eine verantwortliche Person erkennt nach einer Aktualisierung der Quellen, welche Meldungen neu sind, welche eigenen Systeme möglicherweise betroffen sind und warum ein Hinweis eine bestimmte Priorität erhalten hat. Sie kann die zugrunde liegenden Quellen öffnen, die Zuordnung bestätigen oder korrigieren, eine Massnahme dokumentieren und den gesamten Entscheidungsweg später nachvollziehen.

---

## 2. Geltungsbereich und Abgrenzung

### 2.1 Im Geltungsbereich

- Import strukturierter öffentlicher Informationen zu Software-Schwachstellen und aktiver Ausnutzung.

- Anreicherung von CVE-Datensätzen mit Schweregrad, Ausnutzungsindikatoren und Herkunft.

- Import eines autorisierten Systeminventars für Server und virtuelle Maschinen, Anwendungen und Frameworks, Container und Images, Netzwerk- und Sicherheitsgeräte sowie Cloud- und SaaS-Dienste.

- Normalisierung, Dublettenerkennung, Zuordnung und Priorisierung.

- Manuelle Prüfung, Statusführung, Kommentierung und Export.

- Tägliche Triage und Administration im Browser, automatisierte Abläufe per CLI sowie vollständige fachliche Anbindung über eine API.

- Überwachung der Datenquellen und transparente Kennzeichnung von Aktualität und Unsicherheit.

### 2.2 Ausdrücklich ausserhalb des Geltungsbereichs

- Überwachung oder Profilierung von Personen.

- Verarbeitung privater Kommunikation oder nicht öffentlicher Inhalte.

- Umgehung technischer oder rechtlicher Zugangsbeschränkungen.

- Aktive Schwachstellensuche, Port-Scanning, Penetration Testing oder Exploit-Ausführung.

- Automatische Installation von Patches oder Veränderung produktiver Systeme.

- Automatische Verdächtigung oder Bewertung von Personen, Organisationen oder Staaten.

- Garantie, dass ein System tatsächlich verwundbar oder nicht verwundbar ist.

| **Positionierung:** RiskSignal ist ein Werkzeug für Vulnerability Intelligence, Security-Triage und Operational Risk Management – keine Überwachungs- oder Spionagesoftware. |
|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

---

## 3. Stakeholder, Rollen und Verantwortlichkeiten

| **Rolle**             | **Interesse / Aufgabe**                                        | **Berechtigung im System**                                       |
|-----------------------|----------------------------------------------------------------|------------------------------------------------------------------|
| Security Analyst      | Prüft und priorisiert Signale; dokumentiert Entscheidungen.    | Lesen, bewerten, Status ändern, kommentieren, exportieren.       |
| Systemverantwortliche | Beurteilen technische Betroffenheit und planen Massnahmen.     | Zugeordnete Signale lesen und bearbeiten.                        |
| Administrator         | Verwaltet Benutzer, Quellen, Regeln und Inventarimporte.       | Konfiguration und Administration; keine Löschung von Auditdaten. |
| Auditor / Reviewer    | Prüft Herkunft, Entscheidungen und Bearbeitungshistorie.       | Lesender Zugriff auf Signale, Quellen und Auditverlauf.          |
| Product Owner         | Priorisiert Anforderungen und nimmt Produktstände fachlich ab. | Abnahme und Scope-Entscheide ausserhalb des Laufzeitsystems.     |

---

## 4. Informationsquellen

RiskSignal unterscheidet zwischen strukturierten Primärquellen, ergänzenden Hinweisen und autorisierten internen Kontextdaten. Jede Information behält ihre Quelle, den Abrufzeitpunkt und den ursprünglichen Referenzlink.

### 4.1 Quellen des MVP

| **Quelle**              | **Verarbeitete Informationen**                                                                                                                   | **Zweck**                                                                   |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------|
| NVD / CVE API           | CVE-ID, Beschreibung, CVSS, betroffene Produkte/CPE, Referenzen, Änderungszeitpunkt.                                                             | Grundbestand der veröffentlichten Schwachstellen.                           |
| CISA KEV                | CVE-ID, Datum der Aufnahme, Hersteller/Produkt, bekannte aktive Ausnutzung, empfohlene Massnahme und Frist.                                      | Bestätigter Indikator für reale Ausnutzung.                                 |
| FIRST EPSS              | CVE-ID, aktueller EPSS-Wert, Perzentil und Bewertungsdatum.                                                                                      | Ergänzende Wahrscheinlichkeit einer Ausnutzung; kein alleiniger Risikowert. |
| Systeminventar          | Assets mit Typ, Kritikalität, Exposition, Owner und Umgebung sowie zugeordnete Komponenten mit Hersteller, Produkt, Version und Identifikatoren. | Autorisierter Kontext für die Betroffenheitsanalyse.                        |
| Synthetische Testquelle | Definierte Herstellerhinweise und Statusereignisse ohne reale Kundendaten.                                                                       | Reproduzierbare Demonstration und Abnahmetests.                             |

### 4.2 Erweiterungsquellen nach dem MVP

Als erste Erweiterung nach den drei technischen MVP-Kernquellen wird das Bundesamt für Cybersicherheit BACS/NCSC Schweiz priorisiert. Verarbeitet werden ausschliesslich öffentlich zugängliche offizielle Warnungen, Informationen für IT-Fachpersonen sowie Hinweise auf Schwachstellen oder Angriffswellen. Soweit vorhanden, werden Titel, Kurzbeschreibung, Kategorie, Publikations- und Änderungszeit, Referenz, betroffene Produkte und CVE-Kennungen übernommen. BACS-Hinweise ergänzen die Evidenz, gelten aber nicht als Beweis für eine konkrete Betroffenheit.

- BACS/NCSC Schweiz: bevorzugt über strukturierte Feeds oder APIs; andernfalls über einen kontrollierten manuellen Import ohne aggressives Web-Scraping.

- CERT-Bund / BSI: technische Sicherheitshinweise und RSS-Kurzmeldungen.

- Strukturierte Herstellerhinweise ausgewählter Anbieter.

- Öffentliche Statusseiten relevanter Cloud- und Infrastrukturdienste.

- Weitere organisationsspezifisch freigegebene Quellen mit geklärten Nutzungsbedingungen.

Die Aufnahme einer Erweiterungsquelle erfordert vorab eine Prüfung von Formatstabilität, Aktualisierungsintervall, Nutzungsbedingungen, Datenqualität und Ausfallverhalten. Unstrukturierte Webseiten werden nicht ohne explizite Freigabe automatisiert extrahiert.

### 4.3 Quellenvertrauen und Aktualität

Eine Quelle wird nicht pauschal als „wahr“ eingestuft. RiskSignal dokumentiert vielmehr Typ, Herausgeber, Abrufzeitpunkt, technische Integrität, Aktualität und Widersprüche. Offizielle strukturierte Primärquellen erhalten für ihren jeweiligen Aussagebereich ein höheres Grundvertrauen als manuell erfasste oder unbestätigte Hinweise. Die fachliche Bedeutung ergibt sich dennoch erst im Zusammenhang mit dem eigenen Inventar.

---

## 5. Fachlicher Gesamtprozess

| **Schritt**        | **Fachliches Ergebnis**                                                                                                        |
|--------------------|--------------------------------------------------------------------------------------------------------------------------------|
| 1. Abrufen        | RiskSignal ruft freigegebene Quellen nach konfiguriertem Zeitplan oder manuell ab.                                             |
| 2. Validieren     | Format, Pflichtfelder, Zeitstempel und technische Herkunft werden geprüft. Fehlerhafte Datensätze gelangen in eine Quarantäne. |
| 3. Normalisieren  | Quellenspezifische Daten werden in ein gemeinsames Modell aus Schwachstelle, Hinweis, Produkt, Quelle und Evidenz überführt.   |
| 4. Zusammenführen | Mehrere Datensätze zur gleichen CVE werden verknüpft; Originalwerte bleiben erhalten.                                          |
| 5. Anreichern     | KEV-Status, EPSS, CVSS, Herstellerreferenzen und Aktualität werden ergänzt.                                                    |
| 6. Zuordnen       | Produkte und Versionen werden mit dem autorisierten Systeminventar abgeglichen. Jede Zuordnung erhält eine Konfidenz.          |
| 7. Priorisieren   | Aus bestätigten Faktoren wird eine erklärbare Prioritätsklasse abgeleitet.                                                     |
| 8. Prüfen         | Ein Analyst bestätigt, korrigiert oder verwirft die Zuordnung und dokumentiert die Entscheidung.                               |
| 9. Bearbeiten     | Das Signal erhält Status, verantwortliche Person, Massnahme und optional eine Frist.                                           |
| 10. Nachweisen    | Quellenstand, Bewertungsbegründung und Änderungen bleiben im Auditverlauf erhalten.                                            |

### 5.1 Fehler- und Quarantäneprinzip

Ein fehlerhafter Datensatz darf den Import der übrigen Datensätze nicht verhindern. Nicht interpretierbare oder unvollständige Inhalte werden mit Fehlergrund, Quelle und Zeitpunkt in einer Quarantäne abgelegt. Sie dürfen nicht unbemerkt in die Priorisierung einfliessen. Nach Korrektur der Quelle oder Zuordnungsregel kann eine kontrollierte Wiederverarbeitung ausgelöst werden.

---

## 6. Priorisierung und Nachvollziehbarkeit

RiskSignal verwendet keine undurchsichtige Einzahl als alleinige Entscheidungsgrundlage. Das System weist eine Prioritätsklasse aus und zeigt die beitragenden Faktoren separat. Ein EPSS- oder CVSS-Wert wird übernommen und erklärt, aber nicht als Beweis für eine konkrete Betroffenheit interpretiert.

### 6.1 Bewertungsfaktoren

| **Faktor**          | **Beispiele**                                           | **Bedeutung**                                                  |
|---------------------|---------------------------------------------------------|----------------------------------------------------------------|
| Ausnutzung          | CISA KEV: ja/nein; EPSS und Perzentil.                  | Erhöht Dringlichkeit, ersetzt jedoch keine Inventarzuordnung.  |
| Technische Schwere  | CVSS und veröffentlichte Auswirkungen.                  | Beschreibt potenziellen technischen Schaden.                   |
| Zuordnungskonfidenz | Hoch, mittel, niedrig, keine.                           | Zeigt Verlässlichkeit der Produkt-/Versionszuordnung.          |
| Systemkritikalität  | Geschäftskritisch, hoch, normal, niedrig.               | Bildet den internen Geschäftskontext ab.                       |
| Exposition          | Internet-exponiert, intern, isoliert, unbekannt.        | Beeinflusst Erreichbarkeit und Prüfdringlichkeit.              |
| Aktualität          | Abrufzeit, Veröffentlichungszeit, letzte Änderung.      | Warnt vor veralteten oder noch nicht aktualisierten Daten.     |
| Analystenentscheid  | Bestätigt, nicht betroffen, akzeptiert, zurückgestellt. | Dokumentierte menschliche Bewertung hat Vorrang vor Automatik. |

### 6.2 Prioritätsklassen

| **Klasse**       | **Leitregel**                                                                                      | **Erwartete Reaktion**                           |
|------------------|----------------------------------------------------------------------------------------------------|--------------------------------------------------|
| P1 – kritisch    | Hohe Zuordnungskonfidenz, relevante Exposition/Kritikalität und bestätigte aktive Ausnutzung.      | Unverzügliche fachliche Prüfung und Zuweisung.   |
| P2 – hoch        | Hohe Zuordnungskonfidenz und starker Schwere-/Ausnutzungsindikator, jedoch nicht alle P1-Faktoren. | Zeitnahe Prüfung gemäss internem Prozess.        |
| P3 – mittel      | Mögliche Betroffenheit oder mittlere Konfidenz; zusätzliche Abklärung erforderlich.                | Einplanen und Sachverhalt klären.                |
| P4 – Information | Kein bestätigter Inventarbezug oder rein informativer Hinweis.                                     | Beobachten, archivieren oder gezielt ausblenden. |

Schwellenwerte und Kombinationen werden konfigurierbar dokumentiert. Eine manuelle Umstufung ist nur mit Begründung möglich. Jede Priorität muss maschinenlesbar und in verständlicher Sprache erklärbar sein.

### 6.3 Reaktionszeiten im 24/7-Security-Betrieb

Die Reaktionszeiten laufen in realer verstrichener Zeit und bilden einen professionellen, durchgehend besetzten Security-Betrieb ab. Die Benachrichtigung ist die technische Zustellung; die Bestätigung dokumentiert die Übernahme; die qualifizierte Bewertung hält Betroffenheit und Dringlichkeit fest; der Massnahmenentscheid bestimmt das weitere Vorgehen. Eine Behebungsfrist wird separat geführt.

| **Klasse** | **Benachrichtigung** | **Bestätigung**         | **Qualifizierte Bewertung** | **Massnahmenentscheid** |
|------------|----------------------|-------------------------|-----------------------------|-------------------------|
| P1         | ≤ 5 Minuten          | ≤ 15 Minuten            | ≤ 60 Minuten                | ≤ 4 Stunden             |
| P2         | ≤ 15 Minuten         | ≤ 1 Stunde              | ≤ 4 Stunden                 | ≤ 24 Stunden            |
| P3         | Kein Paging          | ≤ 24 Stunden            | ≤ 72 Stunden                | Nach Bewertung          |
| P4         | Kein Paging          | Keine Einzelbestätigung | Wöchentliche Sichtung       | Bei Bedarf              |

Für P1 und P2 erfolgen aktive Benachrichtigungen. Ein unbestätigtes P1-Signal wird nach 15 Minuten eskaliert. Verbleibende Zeit, Fristverletzungen und Eskalationen sind sichtbar und werden auditiert. Eine SLA-Pause ist nur mit dokumentiertem Grund zulässig. Für Demonstrationen dürfen die Zeitwerte verkürzt konfiguriert werden; die fachlichen Regeln bleiben unverändert.

---

## 7. Informationsmodell

| **Objekt**       | **Kerninhalt**                                                                                                   | **Beziehungen**                                          |
|------------------|------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------|
| Quelle           | Name, Herausgeber, Typ, URL, Status, Abrufintervall.                                                             | liefert Quellendatensätze                                |
| Quellendatensatz | Original-ID, Originalinhalt/Hash, Abruf- und Änderungszeit.                                                      | wird zu Evidenz normalisiert                             |
| Schwachstelle    | CVE-ID, Beschreibung, CVSS, Referenzen.                                                                          | besitzt Evidenzen und Signale                            |
| Evidenz          | Aussage, Herkunft, Zeitpunkt, Vertrauens- und Aktualitätsangaben.                                                | begründet Bewertung                                      |
| Komponente       | Hersteller, Produktname, Version, CPE oder alternativer Identifikator, Alias, Image und optional Digest.         | gehört zu einem Asset und wird technisch zugeordnet      |
| Asset            | ID, Name, Typ, Umgebung, Kritikalität, Exposition, Owner, Inventarquelle, letzte Prüfung und Lebenszyklusstatus. | enthält Komponenten und kann von Signalen betroffen sein |
| Zuordnung        | Asset, Schwachstelle, Methode, Konfidenz, Begründung.                                                            | erzeugt oder aktualisiert Signal                         |
| Risikosignal     | Priorität, Status, Begründung, Owner, Frist, Entscheidung.                                                       | zentrale Arbeitseinheit                                  |
| Auditereignis    | Akteur, Zeit, Aktion, alter/neuer Zustand, Referenz.                                                             | dokumentiert jede relevante Änderung                     |

Originaldaten werden nicht stillschweigend überschrieben. Korrigierte oder neu eingetroffene Werte erzeugen eine nachvollziehbare Version beziehungsweise ein Änderungsereignis. Zeitangaben werden intern in UTC gespeichert und in der Oberfläche lokalisiert dargestellt.

Ein Asset kann mehrere Komponenten enthalten. Automatisches Matching im MVP konzentriert sich auf versionierte Komponenten. Cloud- und SaaS-Dienste werden als Assets inventarisiert, jedoch ohne geeignete Produkt- oder Versionsidentifikatoren nicht wie klassische Software automatisch als betroffen behauptet.

---

## 8. Benutzererlebnis und Anwendungsfälle

### 8.1 Zentrale Ansichten

- Dashboard: neue und offene Signale nach Priorität, Alter, Owner und Quelle.

- Signalübersicht: filter- und sortierbare Arbeitsliste.

- Signaldetail: Betroffenheit, Begründung, Quellen, Assetkontext, Status und Historie.

- Quellenmonitor: letzter erfolgreicher Abruf, Datenalter, Fehler und Quarantäne.

- Inventar: Assets, Produktzuordnungen, Importstatus und Datenqualität.

- Administration: Benutzer, Rollen, Prioritätsregeln und Quelleneinstellungen.

### 8.2 Anwendungsfälle

| **ID / Name**                   | **Beschreibung**                                                                                                                                    |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
| UC-01 Inventar importieren      | Administrator importiert eine geprüfte CSV-Datei, erhält eine Voransicht und bestätigt den Import. Fehlerhafte Zeilen werden separat ausgewiesen.   |
| UC-02 Quellen aktualisieren     | Ein geplanter oder manueller Lauf lädt neue und geänderte Datensätze, ohne identische Inhalte doppelt zu speichern.                                 |
| UC-03 Signal prüfen             | Analyst öffnet ein Signal, sieht alle Faktoren und Quellen und bestätigt oder korrigiert die Betroffenheit.                                         |
| UC-04 Bearbeitung dokumentieren | Analyst weist einen Owner zu, setzt Status und Frist und hält nächste Schritte fest.                                                                |
| UC-05 Fehlzuordnung korrigieren | Analyst markiert eine Produktzuordnung als falsch; das System protokolliert Korrektur und verhindert dieselbe Fehlzuordnung nach definierter Regel. |
| UC-06 Quellenfehler behandeln   | Administrator erkennt einen ausgefallenen oder veralteten Feed, untersucht Quarantäne und startet eine Wiederverarbeitung.                          |
| UC-07 Nachweis exportieren      | Reviewer exportiert gefilterte Signale mit Begründung und Quellenstand als CSV oder JSON.                                                           |
| UC-08 Demo reproduzieren        | Eine synthetische Beispieldatenmenge erzeugt deterministisch definierte P1–P4-Signale für Demonstration und Abnahme.                                |

### 8.3 Zugangs- und Bedienkanäle

| **Kanal** | **Aufgabe im MVP**                                                                                          | **Leitplanke**                                                 |
|-----------|-------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------|
| API       | Vollständige fachliche Schnittstelle für Inventar, Quellenläufe, Signale, Status, Audit und Administration. | API-first; versioniert und dokumentiert.                       |
| Browser   | Tägliche Triage, Signaldetail, Dashboard, Quellenmonitor, Inventar- und Benutzeradministration.             | Rollenabhängige Funktionen; keine separate Fachlogik.          |
| CLI       | Automatisierte Importe, Wartungs- und Demoabläufe sowie kontrollierte Administration.                       | Nutzt dieselben Regeln und Berechtigungen wie API und Browser. |

Alle Kanäle verwenden dieselbe Domänenlogik. Ein fachlich gleicher Vorgang muss unabhängig vom Kanal zu demselben Ergebnis, denselben Berechtigungsprüfungen und denselben Auditereignissen führen.

---

## 9. Funktionale Anforderungen

Prioritäten: M = Muss für MVP, S = Soll wenn innerhalb des MVP-Budgets, K = Kann / spätere Ausbaustufe.

| **ID** | **Prio** | **Anforderung**                                                                                                    | **Abnahmekriterium**                                                                                                                                             |
|--------|----------|--------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| FR-001 | M        | Quellen lassen sich mit Name, Typ, URL, Intervall und Aktivstatus registrieren.                                    | Eine freigegebene Quelle kann aktiviert/deaktiviert werden; Änderungen erscheinen im Audit.                                                                      |
| FR-002 | M        | NVD/CVE-Daten werden inkrementell importiert und versioniert.                                                      | Neue und geänderte CVEs erscheinen einmalig mit Abruf- und Änderungszeit.                                                                                        |
| FR-003 | M        | Der CISA-KEV-Katalog wird importiert und mit vorhandenen CVEs verknüpft.                                           | Ein KEV-Eintrag markiert die richtige CVE und zeigt Aufnahmedatum sowie Originalreferenz.                                                                        |
| FR-004 | M        | EPSS-Werte werden für relevante CVEs angereichert.                                                                 | Wert, Perzentil und Bewertungsdatum sind sichtbar; fehlende Werte werden als fehlend markiert.                                                                   |
| FR-005 | M        | Ein synthetischer Feed steht für Demo und Tests zur Verfügung.                                                     | Der definierte Datensatz lässt sich wiederholt ohne Dubletten importieren.                                                                                       |
| FR-006 | M        | Systeminventare können per CSV importiert werden.                                                                  | Voransicht, Validierung, Fehlerbericht und bestätigter Import funktionieren mit Referenzdatei.                                                                   |
| FR-007 | M        | Pflichtfelder und zulässige Werte des Inventars werden validiert.                                                  | Ungültige Zeilen werden abgewiesen, gültige Zeilen bleiben importierbar.                                                                                         |
| FR-008 | M        | Quellendaten werden in ein gemeinsames fachliches Modell normalisiert.                                             | Gleiche CVE aus mehreren Quellen erscheint als eine Schwachstelle mit mehreren Evidenzen.                                                                        |
| FR-009 | M        | Importe sind idempotent und erkennen unveränderte Datensätze.                                                      | Zweifacher Import identischer Daten verändert Anzahl und Inhalt fachlicher Objekte nicht.                                                                        |
| FR-010 | M        | Fehlerhafte Datensätze gelangen mit Fehlergrund in Quarantäne.                                                     | Fehler blockiert übrigen Import nicht und ist im Quellenmonitor sichtbar.                                                                                        |
| FR-011 | M        | Assets werden anhand CPE, Produktalias und Version zugeordnet.                                                     | Referenzfälle ergeben erwartete Zuordnung und dokumentierte Konfidenz.                                                                                           |
| FR-012 | M        | Jede automatische Zuordnung erhält Methode, Konfidenz und Begründung.                                              | Signaldetail zeigt, wodurch die Zuordnung zustande kam.                                                                                                          |
| FR-013 | M        | Prioritätsklassen P1–P4 werden deterministisch aus konfigurierten Faktoren abgeleitet.                             | Referenzdatensatz liefert die erwartete Klasse und Einzelbegründung.                                                                                             |
| FR-014 | M        | Signale besitzen Status Neu, In Prüfung, Massnahme geplant, Erledigt, Akzeptiert und Nicht betroffen.              | Erlaubte Übergänge funktionieren; ungültige Übergänge werden abgewiesen.                                                                                         |
| FR-015 | M        | Owner, Frist, Kommentar und Entscheidungsbegründung können gepflegt werden.                                        | Änderungen bleiben nach Neustart erhalten und sind im Audit sichtbar.                                                                                            |
| FR-016 | M        | Manuelle Bestätigung, Korrektur und Umstufung sind mit Begründung möglich.                                         | Ohne Begründung wird eine fachliche Übersteuerung nicht gespeichert.                                                                                             |
| FR-017 | M        | Signale können nach Priorität, Status, Asset, Produkt, CVE, Owner und Zeitraum gefiltert werden.                   | Kombinierte Filter liefern nur passende Referenzfälle.                                                                                                           |
| FR-018 | M        | Das Signaldetail zeigt Quellen, Aktualität, Inventarbezug und Bewertungsfaktoren.                                  | Alle für die Priorität verwendeten Faktoren sind sichtbar und verlinkt.                                                                                          |
| FR-019 | M        | Relevante Änderungen erzeugen unveränderbare Auditereignisse.                                                      | Akteur, Zeitpunkt, Aktion und Zustandsänderung sind nachweisbar.                                                                                                 |
| FR-020 | M        | Der Quellenmonitor zeigt Erfolg, Fehler, Laufzeit, Datensätze und Datenalter.                                      | Ausfall und anschliessende Erholung einer Testquelle werden korrekt dargestellt.                                                                                 |
| FR-021 | S        | Quarantänedatensätze können nach Korrektur erneut verarbeitet werden.                                              | Ein korrigierter Referenzdatensatz wird übernommen; Fehlerhistorie bleibt erhalten.                                                                              |
| FR-022 | S        | Gefilterte Signalübersichten können als CSV und JSON exportiert werden.                                            | Export enthält Filterumfang, Erstellzeit und fachliche Kernfelder.                                                                                               |
| FR-023 | S        | Benutzer können gezielt Benachrichtigungen für neue P1/P2-Signale konfigurieren.                                   | Ein Referenzsignal erzeugt genau eine Benachrichtigung; Wiederholung erzeugt kein Duplikat.                                                                      |
| FR-024 | K        | BACS/NCSC Schweiz wird als erste Erweiterungsquelle integriert; weitere Adapter folgen nach Priorisierung.         | Offizielle öffentliche Inhalte werden mit Herkunft und Aktualität verarbeitet; fehlt ein strukturierter Zugang, ist ein kontrollierter manueller Import möglich. |
| FR-025 | M        | Die versionierte API stellt alle fachlichen MVP-Funktionen bereit.                                                 | Inventar, Quellenläufe, Signale, Status, Audit und Administration sind dokumentiert aufrufbar.                                                                   |
| FR-026 | M        | Eine CLI unterstützt automatisierte Importe, Wartungs- und Demoabläufe.                                            | Referenzabläufe sind nicht-interaktiv, wiederholbar und liefern auswertbare Exit-Codes.                                                                          |
| FR-027 | M        | Browseroberflächen unterstützen tägliche Triage und Administration.                                                | Analysten und Administratoren können die jeweils vorgesehenen Aufgaben ohne CLI ausführen.                                                                       |
| FR-028 | M        | Authentisierung erfolgt über OIDC; Berechtigungen werden durch interne Rollen abgebildet.                          | Security Analyst, Systemverantwortliche, Administrator, Auditor und Product Owner erhalten nur freigegebene Funktionen.                                          |
| FR-029 | M        | Ein lokaler Entwicklungsmodus ohne externen Identity Provider ist technisch auf lokale Nutzung begrenzt.           | Der Bypass kann in einer privaten Online-Demoumgebung nicht aktiviert werden.                                                                                    |
| FR-030 | M        | Das Inventar bildet alle vereinbarten Assettypen und mehrere versionierte Komponenten je Asset ab.                 | Pflichtfelder, Beziehungen und Datenqualität entsprechen Abschnitt 7; Cloud/SaaS wird ohne technische Evidenz nicht als betroffen behauptet.                     |
| FR-031 | M        | Das System berechnet und visualisiert Reaktionsfristen, Verletzungen und Eskalationen gemäss Abschnitt 6.3.        | P1/P2 werden aktiv benachrichtigt; ein unbestätigtes P1 eskaliert nach 15 Minuten; alle Ereignisse sind auditiert.                                               |
| FR-032 | M        | Reaktionszeiten lassen sich für Demo und Test kontrolliert verkürzen.                                              | Konfiguration ändert nur Zeitwerte, nicht Prioritäts-, Eskalations- oder Auditlogik.                                                                             |
| FR-033 | M        | Abgeschlossene Risikosignale und ihr Auditverlauf werden standardmässig fünf Jahre nach Abschluss aufbewahrt.      | Vor Ablauf erfolgt keine automatische Löschung; Fristablauf wird kontrolliert und auditiert verarbeitet.                                                         |
| FR-034 | K        | Die Schnittstellenarchitektur ermöglicht eine spätere bidirektionale Statussynchronisation mit Ticketing-Systemen. | Synchronisation ist idempotent, verhindert Schleifen, zeigt Fehler und Konflikte und überschreibt keine widersprüchlichen Zustände stillschweigend.              |

---

## 10. Nichtfunktionale Anforderungen

| **ID**  | **Prio** | **Anforderung**                                                                 | **Abnahmekriterium**                                                                                            |
|---------|----------|---------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| NFR-001 | M        | Das System muss lokal reproduzierbar bereitgestellt werden können.              | Ein dokumentierter Start erzeugt aus leerer Umgebung ein lauffähiges System mit Demo-Daten.                     |
| NFR-002 | M        | Verarbeitung muss ausfallsicher und fortsetzbar sein.                           | Abbruch während Import führt nach Neustart weder zu Verlust noch zu Dubletten.                                  |
| NFR-003 | M        | Interaktive Listen und Details müssen responsiv sein.                           | 95 % der Referenzabfragen antworten bei 250’000 CVEs und 10’000 Assets in ≤ 2 s.                                |
| NFR-004 | M        | Ein inkrementeller Quellenlauf muss zeitnah abgeschlossen werden.               | Täglicher Referenzlauf wird nach Abruf innerhalb von 15 Minuten verarbeitet.                                    |
| NFR-005 | M        | Zeitstempel, Quellen und Entscheidungen müssen nachvollziehbar sein.            | Abnahmefall lässt sich vollständig vom Signal bis zum Originaldatensatz zurückverfolgen.                        |
| NFR-006 | M        | Fehler dürfen keine sensiblen Konfigurationen offenlegen.                       | Logs und Fehlermeldungen enthalten keine Passwörter, Tokens oder Verbindungszeichenfolgen.                      |
| NFR-007 | M        | Alle externen Aufrufe besitzen Timeout, Retry und begrenzte Wiederholungen.     | Simulierter Ausfall endet kontrolliert und wird im Quellenmonitor ausgewiesen.                                  |
| NFR-008 | M        | Fachlogik muss automatisiert testbar sein.                                      | Priorisierung, Matching und Statusübergänge besitzen Unit- und Integrationsprüfungen für Referenzfälle.         |
| NFR-009 | M        | Go-Code erfüllt definierte Qualitätsprüfungen.                                  | Formatierung, statische Analyse, Tests und Race-Detection laufen in CI erfolgreich.                             |
| NFR-010 | S        | Das System stellt strukturierte Logs, Metriken und Health-Informationen bereit. | Importlauf und Fehler lassen sich anhand Korrelation-ID und Metriken nachvollziehen.                            |
| NFR-011 | S        | Daten können gesichert und wiederhergestellt werden.                            | Backup der Referenzdaten wird in neuer Instanz erfolgreich restauriert.                                         |
| NFR-012 | S        | Abhängigkeiten und Images werden nachvollziehbar dokumentiert.                  | Build erzeugt eine Komponentenliste/SBOM und verwendet versionierte Abhängigkeiten.                             |
| NFR-013 | M        | API, Browser und CLI verwenden dieselbe Fach- und Berechtigungslogik.           | Ein identischer Referenzvorgang erzeugt kanalunabhängig denselben Zustand und Auditnachweis.                    |
| NFR-014 | M        | Online-Betrieb ist ohne eigene Passwortspeicherung möglich.                     | Anmeldung erfolgt über OIDC; Tokens und technische Identitäten werden sicher validiert und nicht protokolliert. |
| NFR-015 | M        | Zeit- und Aufbewahrungsregeln sind deterministisch, konfigurierbar und testbar. | Simulierte Zeitverläufe ergeben reproduzierbare Fristen, Eskalationen und Löschentscheidungen.                  |

---

## 11. Datenschutz, Sicherheit und ethische Leitplanken

### 11.1 Datenminimierung

Das MVP benötigt ausser den minimalen Identitäts- und Verantwortungsangaben der berechtigten Benutzer keine personenbezogenen Daten. Authentisierung erfolgt über OIDC; RiskSignal implementiert und speichert keine eigenen Passwörter. Inventardaten werden auf die für Zuordnung, Priorisierung und Zuständigkeit erforderlichen Angaben begrenzt. Freitextfelder werden nicht für geheime oder besonders schützenswerte Inhalte vorgesehen.

### 11.2 Schutzmassnahmen

- OIDC-basierte Authentisierung und rollenbasierte Zugriffssteuerung nach dem Least-Privilege-Prinzip.

- Lokale Mehrrollen-Nutzung und private Online-Demoumgebung; ein Entwicklungs-Bypass ist ausschliesslich lokal zulässig und online technisch gesperrt.

- CLI und Automationen verwenden kontrollierte technische Identitäten beziehungsweise kurzlebige Tokens.

- Sichere Speicherung von Zugangsdaten ausserhalb des Quellcodes.

- Transportverschlüsselung für externe und produktive interne Verbindungen.

- Eingabevalidierung sowie Schutz vor CSV- und Export-Formelinjektion.

- Auditierung fachlich und administrativ relevanter Änderungen.

- Definierte Aufbewahrung und kontrollierte Löschung nicht mehr benötigter Betriebsdaten.

- Keine aktive Interaktion mit den in Meldungen genannten Zielsystemen.

### 11.3 Aufbewahrung und Löschung

| **Datenart**                             | **Standardfrist**                   | **Regel**                                                                  |
|------------------------------------------|-------------------------------------|----------------------------------------------------------------------------|
| Offene Risikosignale                     | Bis zum Abschluss                   | Keine automatische Löschung während der Bearbeitung.                       |
| Abgeschlossene Risikosignale             | 5 Jahre nach Abschluss              | Danach kontrollierte Löschung oder Anonymisierung gemäss Betriebsvorgabe.  |
| Auditereignisse                          | 5 Jahre nach Abschluss des Signals  | Bleiben mindestens so lange wie das zugehörige Signal nachweisbar.         |
| Normalisierte Evidenzen                  | Mindestens bis Ende der Signalfrist | Dürfen den Nachweis des Signals nicht vorzeitig entwerten.                 |
| Quarantäne- und technische Betriebsdaten | Konfigurierbar                      | Werden nach Zweck, Fehlerbehebung und geltender Betriebsvorgabe minimiert. |

Aufbewahrungsfristen werden anhand dokumentierter Abschlusszeitpunkte berechnet. Löschläufe sind berechtigt, nachvollziehbar und auditiert. Gesetzliche, vertragliche oder untersuchungsbezogene Sperren haben Vorrang und müssen begründet dokumentiert werden.

### 11.4 Ethische Leitplanken

RiskSignal bewertet technische Meldungen und autorisierte Assets, nicht Menschen. Quellen müssen öffentlich oder ausdrücklich freigegeben sein. Automatisierte Schlussfolgerungen werden als Hinweise mit Unsicherheit dargestellt. Eine menschliche Person verantwortet jede operative Entscheidung. Neue Datenquellen und neue Bewertungsfaktoren werden vor Aktivierung auf Zweckbindung, Verzerrung, Fehlinterpretation und rechtliche Zulässigkeit geprüft.

---

## 12. Betriebs- und Fehlerkonzept

| **Situation**            | **Systemverhalten**                                                                                     | **Betriebliche Reaktion**                                          |
|--------------------------|---------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| Quelle nicht erreichbar  | Letzter erfolgreicher Stand bleibt lesbar; Quelle wird als verzögert markiert; begrenzte Wiederholung.  | Administrator prüft Quelle; keine Löschung bestehender Evidenz.    |
| Formatänderung           | Validierung schlägt kontrolliert fehl; betroffene Datensätze in Quarantäne.                             | Adapter anpassen und Wiederverarbeitung testen.                    |
| Teilimport               | Erfolgreiche Datensätze werden eindeutig gebucht; Checkpoint erlaubt Fortsetzung.                       | Lauf fortsetzen; Dublettenprüfung kontrollieren.                   |
| Widersprüchliche Angaben | Beide Aussagen bleiben als Evidenz sichtbar; Konflikt wird markiert.                                    | Analyst entscheidet anhand Herkunft und Aktualität.                |
| Inventar veraltet        | Datenalter wird sichtbar; Prioritäten erhalten Warnhinweis.                                             | Inventarverantwortliche aktualisieren Bestand.                     |
| Unbekannte Version       | Zuordnung höchstens mit reduzierter Konfidenz.                                                          | Version abklären; keine automatische Behauptung der Betroffenheit. |
| Systemneustart           | Offene Arbeit und Status bleiben erhalten; unfertige Jobs werden sicher fortgesetzt oder neu gestartet. | Health-Check und Quellenstatus prüfen.                             |

### 12.1 Spätere Ticketing-Integration

Die konkrete Ticketing-Anbindung ist nicht Bestandteil des MVP. Die API und das Ereignismodell werden jedoch so ausgelegt, dass eine spätere bidirektionale Statussynchronisation möglich ist. RiskSignal bleibt führend für Risikobewertung, Priorität, Betroffenheit und Evidenzen; das Ticketing-System bleibt führend für die operative Behebungsaufgabe.

- Ein Risikosignal kann mit einem bestehenden oder neu erstellten Ticket verknüpft werden.

- Statusänderungen werden in beide Richtungen synchronisiert, sofern die Zuordnung eindeutig ist.

- Konflikte erzeugen einen sichtbaren Prüfhinweis und niemals ein stilles Überschreiben.

- Synchronisation ist idempotent, verhindert Rückkopplungsschleifen und wiederholt fehlgeschlagene Übertragungen kontrolliert.

- Ticket-ID, Zielsystem, letzter Synchronisationszeitpunkt und Fehlerzustand sind sichtbar; automatische Änderungen werden auditiert.

- Die automatische Erstellung von P1/P2-Tickets bleibt ein separater Folgeentscheid.

---

## 13. MVP, Ausbaustufen und Umsetzungsstruktur

### 13.1 MVP-Umfang

- NVD/CVE-, CISA-KEV- und EPSS-Integration.

- Inventar für alle vereinbarten Assettypen mit mehreren versionierten Komponenten je Asset, CSV-Import, Validierung und Produktaliasen.

- Normalisierung, idempotenter Import, Quarantäne und Quellenmonitor.

- Deterministische Komponenten- und Asset-Zuordnung mit Konfidenz.

- Erklärbare P1–P4-Priorisierung mit Reaktionsfristen und Eskalationen für den 24/7-Betrieb.

- API-first-Umsetzung mit Browseroberfläche für Triage und Administration sowie CLI für automatisierte Abläufe.

- OIDC-Authentisierung, interne Rollen und ausschliesslich lokaler Entwicklungsmodus.

- Auditverlauf, fünfjährige Aufbewahrung abgeschlossener Signale und CSV/JSON-Export.

- Synthetischer Referenzdatensatz für Demo und Abnahme.

- Reproduzierbare lokale Bereitstellung, private Online-Demoumgebung und automatisierte Qualitätsprüfungen.

### 13.2 Nicht Bestandteil des MVP

- Automatisches Patchen oder eine konkrete Ticketing-Integration; vorgesehen ist nur die integrationsfähige Schnittstellenarchitektur.

- KI-basierte Textklassifikation oder generative Zusammenfassungen.

- Breite Sammlung unstrukturierter Nachrichten- oder Social-Media-Inhalte.

- Mehrmandantenfähigkeit und hochverfügbarer Produktionsbetrieb.

- BACS/NCSC-, CERT-Bund-, Hersteller- und Statusseitenadapter über den vereinbarten MVP hinaus.

### 13.3 Empfohlene Arbeitspakete

| **AP** | **Ergebnis**        | **Inhalt**                                                                                             | **Anforderungen**                                                  |
|--------|---------------------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------|
| AP-01  | Projektgrundlage    | Repository, Qualitätsregeln, Build, lokale Laufzeit, Dokumentation.                                    | NFR-001, NFR-009, NFR-012                                          |
| AP-02  | Domänenmodell       | Quellen, CVEs, Evidenzen, Assets, Komponenten, Zuordnungen, Signale, Audit und Integrationsereignisse. | FR-008, FR-019, FR-030, FR-034                                     |
| AP-03  | Quellenintegration  | NVD, KEV, EPSS, synthetischer Feed, Monitoring und Quarantäne.                                         | FR-001–005, FR-009–010, FR-020–021                                 |
| AP-04  | Inventar & Matching | Assettypen, Komponenten, CSV-Import, Validierung, Aliasse, Versionen und Konfidenz.                    | FR-006–007, FR-011–012, FR-030                                     |
| AP-05  | Priorisierung & SLA | Regelwerk, Erklärungen, Reaktionsfristen, Eskalationen, Referenzfälle und manuelle Übersteuerung.      | FR-013, FR-016, FR-031–032, NFR-008                                |
| AP-06  | API, Web & CLI      | Versionierte API, Dashboard, Triage, Administration, Filter, Detail und Automationsbefehle.            | FR-014–018, FR-025–027, NFR-013                                    |
| AP-07  | Security & Betrieb  | OIDC, Rollen, lokaler Modus, Aufbewahrung, Secrets, Logs, Health, Backup und Fehlerfälle.              | FR-028–029, FR-033, NFR-002, NFR-006–007, NFR-010–011, NFR-014–015 |
| AP-08  | Abnahme & Nachweis  | Demo-Daten, End-to-End-Tests, Performance, Export und Abnahmeprotokoll.                                | FR-022–023, AT-001–AT-021                                          |

### 13.4 Empfohlene Umsetzungsreihenfolge

1.  Iteration 1: Projektgrundlage, API-Skelett, Domänenmodell und synthetischer End-to-End-Durchstich.

2.  Iteration 2: NVD/KEV/EPSS und robuste Importverarbeitung.

3.  Iteration 3: Inventarmodell, Import, Matching, Priorisierung und Reaktionsfristen.

4.  Iteration 4: Browseroberfläche, CLI, OIDC/Rollen, Statusworkflow und Audit.

5.  Iteration 5: Aufbewahrung, Betriebsqualität, private Online-Demo, Performance, Dokumentation und formelle Abnahme.

Jede Iteration endet mit einem demonstrierbaren, testbaren Stand. Die Detailplanung schätzt Aufwand erst nach technischer Klärung der jeweiligen Quellenformate und der gewünschten Benutzeroberfläche.

---

## 14. Abnahmekonzept und Abnahmematrix

Die Abnahme erfolgt anhand eines versionierten Referenzdatensatzes und einer definierten Testumgebung. Jeder Testfall dokumentiert Datum, Version/Commit, ausführende Person, erwartetes Ergebnis, tatsächliches Ergebnis, Nachweise, Abweichungen und Entscheid. Eine Anforderung gilt erst als abgenommen, wenn alle zugeordneten Muss-Testfälle erfolgreich sind oder eine schriftlich akzeptierte Abweichung besteht.

### 14.1 Eingangskriterien

- Abnahmekandidat ist eindeutig versioniert und reproduzierbar bereitstellbar.

- Alle Muss-Anforderungen sind umgesetzt oder als bekannte Abweichung dokumentiert.

- Automatisierte Qualitätsprüfungen sind erfolgreich.

- Referenzdaten, Importdateien und erwartete Ergebnisse sind versioniert.

- Installations-, Betriebs- und Benutzerdokumentation liegen vor.

- Keine offenen Fehler der Schwere Blocker oder Kritisch.

### 14.2 Abnahmematrix

| **ID** | **Prüfung**              | **Vorgehen**                                                                                                             | **Erwartetes Ergebnis**                                                                                                              | **Bezug**           |
|--------|--------------------------|--------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|---------------------|
| AT-001 | Reproduzierbarer Start   | Leere Zielumgebung gemäss Anleitung starten.                                                                             | Anwendung, Datenbank und Health-Checks sind betriebsbereit.                                                                          | NFR-001             |
| AT-002 | Idempotenter Import      | Identische MVP-Quelldaten zweimal importieren.                                                                           | Keine fachlichen Dubletten; zweiter Lauf meldet unveränderte Datensätze.                                                             | FR-002–005, FR-009  |
| AT-003 | Quarantäne               | Feed mit einem fehlerhaften und zwei gültigen Datensätzen importieren.                                                   | Zwei gültige verarbeitet; Fehler mit Grund in Quarantäne.                                                                            | FR-010              |
| AT-004 | Inventarvalidierung      | Referenz-CSV mit gültigen und ungültigen Zeilen prüfen und importieren.                                                  | Voransicht und Fehlerbericht stimmen; nur bestätigte gültige Zeilen gespeichert.                                                     | FR-006–007          |
| AT-005 | Asset-Matching           | Definierte Produkt-/Versionsfälle ausführen.                                                                             | Zuordnung, Nichtzuordnung und Konfidenz entsprechen Erwartungsmatrix.                                                                | FR-011–012          |
| AT-006 | P1-Priorität             | KEV-CVE einem kritischen, exponierten Asset eindeutig zuordnen.                                                          | P1-Signal mit vollständiger Begründung entsteht.                                                                                     | FR-013, FR-018      |
| AT-007 | Unsicherheit             | CVE nur über ungenauen Alias und ohne Version zuordnen.                                                                  | Keine sichere Betroffenheitsbehauptung; reduzierte Konfidenz und Prüfhinweis.                                                        | FR-011–013          |
| AT-008 | Statusworkflow           | Signal durch erlaubte und unerlaubte Statusübergänge führen.                                                             | Erlaubte gespeichert; unerlaubte abgewiesen und protokolliert.                                                                       | FR-014, FR-019      |
| AT-009 | Manuelle Korrektur       | Zuordnung und Priorität mit Begründung korrigieren.                                                                      | Korrektur wirksam; Ursprung und alter/neuer Wert im Audit.                                                                           | FR-016, FR-019      |
| AT-010 | Filter & Suche           | Kombinierte Filter auf Referenzbestand anwenden.                                                                         | Ergebnis entspricht definierter Treffermenge.                                                                                        | FR-017              |
| AT-011 | Quellenausfall           | Timeout und Formatfehler einer Quelle simulieren.                                                                        | Kontrollierter Fehler, begrenzter Retry, Quelle verzögert/fehlerhaft; Altbestand bleibt verfügbar.                                   | FR-020, NFR-007     |
| AT-012 | Fortsetzung              | Importprozess kontrolliert unterbrechen und neu starten.                                                                 | Verarbeitung wird verlust- und dublettenfrei fortgesetzt.                                                                            | NFR-002             |
| AT-013 | Performance              | Referenzvolumen laden und definierte Abfragen/Importe messen.                                                            | Grenzwerte aus NFR-003 und NFR-004 werden eingehalten.                                                                               | NFR-003–004         |
| AT-014 | Export                   | Gefilterte Signale als CSV und JSON exportieren.                                                                         | Inhalt, Filterkontext, Zeitstempel und Schutz vor Formelinjektion geprüft.                                                           | FR-022, NFR-006     |
| AT-015 | Backup/Restore           | Referenzinstallation sichern und in neuer Instanz wiederherstellen.                                                      | Objekte, Status und Auditverlauf stimmen mit Ausgangsstand überein.                                                                  | NFR-011             |
| AT-016 | API-Abdeckung            | Definierte MVP-Geschäftsvorgänge ausschliesslich über die dokumentierte API ausführen.                                   | Alle Vorgänge liefern erwartete Zustände, Berechtigungsprüfungen und Auditereignisse.                                                | FR-025, NFR-013     |
| AT-017 | CLI-Automation           | Referenzimport und Demoablauf nicht-interaktiv per CLI zweimal ausführen.                                                | Auswertbare Exit-Codes, deterministisches Ergebnis und keine Dubletten.                                                              | FR-026, NFR-013     |
| AT-018 | OIDC und Rollen          | Benutzer aller Rollen anmelden; erlaubte und verbotene Aktionen prüfen; Online-Konfiguration mit lokalem Bypass starten. | Rollen wirken gemäss Konzept; verbotene Aktionen werden abgewiesen; Online-Start mit Bypass scheitert sicher.                        | FR-028–029, NFR-014 |
| AT-019 | Assettypen & Komponenten | Referenzinventar mit allen vereinbarten Assettypen und mehreren Komponenten importieren.                                 | Struktur bleibt erhalten; versionierte Komponenten werden korrekt zugeordnet; Cloud/SaaS ohne Evidenz nicht als betroffen behauptet. | FR-030              |
| AT-020 | SLA und Eskalation       | P1–P4 mit verkürzten Demo-Zeitwerten durch alle Fristzustände führen.                                                    | Anzeige, Benachrichtigung, P1-Eskalation, Verletzung und Audit entsprechen Abschnitt 6.3.                                            | FR-031–032, NFR-015 |
| AT-021 | Aufbewahrung             | Abschluss- und Ablaufzeitpunkte mit simulierter Zeit vor und nach der Fünfjahresgrenze prüfen.                           | Vor Fristende keine Löschung; danach kontrollierter, berechtigter und auditierter Lauf.                                              | FR-033, NFR-015     |

### 14.3 Vorlage für das spätere Abnahmeprotokoll

| **Feld**        | **Eintrag**                                                                                                      |
|-----------------|------------------------------------------------------------------------------------------------------------------|
| Abnahmekandidat | Version / Commit / Build: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_                           |
| Testumgebung    | \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ |
| Testfall        | AT-\_\_\_\_ Bezeichnung: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_              |
| Durchführung    | Datum: \_\_\_\_\_\_\_\_\_\_\_\_\_\_ Person: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_               |
| Ergebnis        | ☐ Bestanden ☐ Mit Abweichung bestanden ☐ Nicht bestanden                                                         |
| Nachweis        | Log, Screenshot, Export oder Testreport: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_                              |
| Abweichung      | Beschreibung / Ticket / Frist: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_                      |
| Entscheid       | ☐ Abgenommen ☐ Bedingt abgenommen ☐ Zurückgewiesen                                                               |
| Freigabe        | Product Owner: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ Datum: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_              |

---

## 15. Annahmen, getroffene Entscheide und Risiken

### 15.1 Arbeitsannahmen

- MVP wird als Einzelmandantenlösung mit synthetischen beziehungsweise freigegebenen Inventardaten entwickelt.

- Öffentliche Quellen dürfen gemäss ihren Nutzungsbedingungen für den beschriebenen Zweck abgerufen werden.

- Produkt- und Versionsdaten im Inventar sind ausreichend gepflegt, um eine sinnvolle Zuordnung zu ermöglichen.

- Prioritäten unterstützen Entscheidungen, ersetzen aber keine technische Verifikation durch Verantwortliche.

- Produktionsbetrieb und Sicherheitsklassifikation werden separat entschieden; dieses Konzept beschreibt zunächst Demo/MVP.

### 15.2 Getroffene Grundsatzentscheide

| **ID** | **Entscheid**                                                                                                    | **Auswirkung**                                                             |
|--------|------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| OD-01  | API-first; Browser für Triage und Administration; CLI für Automation.                                            | Verbindlich für MVP und Kanalparität.                                      |
| OD-02  | OIDC mit internen Rollen; lokale Mehrrollen-Nutzung und private Online-Demo. Lokaler Bypass nur für Entwicklung. | Keine eigene Passwortverwaltung; Online-Schutz ist Abnahmekriterium.       |
| OD-03  | Inventar umfasst Server/VM, Anwendungen/Frameworks, Container/Images, Netzwerk-/Security-Geräte und Cloud/SaaS.  | Asset-Komponenten-Modell gemäss Abschnitt 7.                               |
| OD-04  | BACS/NCSC Schweiz ist die erste Erweiterungsquelle nach NVD, CISA KEV und EPSS.                                  | Priorisiert die Adapter-Roadmap nach dem MVP.                              |
| OD-05  | Reaktionszeiten bilden einen professionellen 24/7-Security-Betrieb ab.                                           | Verbindliche P1–P4-Ziele, Eskalation und SLA-Anzeige gemäss Abschnitt 6.3. |
| OD-06  | Abgeschlossene Risikosignale und Auditverlauf werden standardmässig fünf Jahre aufbewahrt.                       | Bestimmt Nachweis-, Speicher- und Löschkonzept.                            |
| OD-07  | Spätere Ticketing-Integration synchronisiert Status in beide Richtungen.                                         | MVP schafft Integrationsvertrag; konkreter Adapter folgt nach dem MVP.     |

### 15.3 Folgeentscheide für die Detailplanung

- Konkreter OIDC-Anbieter und Claims-/Rollenzuordnung für die Zielumgebung.

- Technischer Bezugsweg und zulässiges Aktualisierungsintervall der BACS/NCSC-Inhalte.

- Zielprodukt, Statusmapping und Authentisierungsverfahren der späteren Ticketing-Integration.

- Ob und unter welchen Bedingungen P1/P2-Signale automatisch neue Tickets erzeugen dürfen.

- Betriebsspezifische Fristen für Quarantäne, Rohdaten und technische Logs innerhalb der Datenminimierungsvorgaben.

### 15.4 Projektrisiken

| **ID** | **Risiko**                                                       | **Einstufung** | **Massnahme**                                                                      |
|--------|------------------------------------------------------------------|----------------|------------------------------------------------------------------------------------|
| R-01   | Unvollständige Produkt-/Versionsdaten führen zu Fehlzuordnungen. | Hoch           | Konfidenz, Datenqualitätswarnung, manuelle Prüfung und Referenzfälle.              |
| R-02   | Externe Quellen ändern Format oder Verfügbarkeit.                | Mittel         | Adapter, Schema-Validierung, Quarantäne, Monitoring und gespeicherter Altstand.    |
| R-03   | Priorität wird als objektive Wahrheit missverstanden.            | Hoch           | Erklärbare Faktoren, Unsicherheit, menschlicher Entscheid und klare UI-Texte.      |
| R-04   | MVP wird durch zu viele Quellen oder Integrationen überladen.    | Hoch           | Verbindlicher MVP-Scope und Erweiterungen erst nach Kernabnahme.                   |
| R-05   | Öffentliche Daten sind widersprüchlich oder verzögert.           | Mittel         | Evidenzen getrennt halten, Aktualität anzeigen, Konflikte markieren.               |
| R-06   | Demo-Positionierung wird fälschlich als Überwachung verstanden.  | Mittel         | Klare Abgrenzung, keine Personendaten, kein Scanning, produktiver Nutzen im Fokus. |

---

## 16. Glossar und Referenzen

### 16.1 Glossar

| **Begriff**  | **Bedeutung**                                                                                     |
|--------------|---------------------------------------------------------------------------------------------------|
| Asset        | Ein autorisiert erfasstes IT-System oder eine Komponente im Inventar.                             |
| CPE          | Standardisierte Produktbezeichnung, die beim Abgleich von Produkten und Versionen unterstützt.    |
| CVE          | Öffentliche Kennung für eine bekannte Schwachstelle.                                              |
| CVSS         | Standardisierter technischer Schweregrad einer Schwachstelle.                                     |
| EPSS         | Wahrscheinlichkeitsbasierte Einschätzung, ob eine CVE in einem Zeitraum ausgenutzt werden könnte. |
| Evidenz      | Quellengebundene Aussage, die eine Bewertung unterstützt oder ihr widerspricht.                   |
| KEV          | Katalog von Schwachstellen, für die aktive Ausnutzung bekannt ist.                                |
| Konfidenz    | Transparente Einschätzung der Verlässlichkeit einer Zuordnung.                                    |
| Risikosignal | Priorisierte, begründete Arbeitseinheit aus Schwachstelle, Assetbezug und Evidenzen.              |
| Triage       | Sichtung, Einordnung und Zuweisung eines Hinweises zur weiteren Bearbeitung.                      |

### 16.2 Referenzen und vorgesehene Primärquellen

- NVD Developer APIs: [<u>https://nvd.nist.gov/developers</u>](https://nvd.nist.gov/developers)

- NVD Vulnerability API: [<u>https://nvd.nist.gov/developers/vulnerabilities</u>](https://nvd.nist.gov/developers/vulnerabilities)

- NVD Terms of Use: [<u>https://nvd.nist.gov/developers/terms-of-use</u>](https://nvd.nist.gov/developers/terms-of-use)

- CISA Known Exploited Vulnerabilities Catalog: [<u>https://www.cisa.gov/known-exploited-vulnerabilities-catalog</u>](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

- FIRST EPSS – Get the Data: [<u>https://www.first.org/epss/data</u>](https://www.first.org/epss/data)

- FIRST EPSS API: [<u>https://api.first.org/epss/</u>](https://api.first.org/epss/)

- Bundesamt für Cybersicherheit BACS / NCSC Schweiz: [<u>https://www.bacs.admin.ch/</u>](https://www.bacs.admin.ch/)

- BSI / CERT-Bund RSS-Feeds: [<u>https://www.bsi.bund.de/DE/Service-Navi/Abonnements/RSS/rss_node.html</u>](https://www.bsi.bund.de/DE/Service-Navi/Abonnements/RSS/rss_node.html)

### 16.3 Änderungshistorie

| **Version** | **Datum**  | **Änderung**                                                                                            | **Status** |
|-------------|------------|---------------------------------------------------------------------------------------------------------|------------|
| 0.2         | 08.09.2026 | Grundsatzentscheide OD-01 bis OD-07 eingearbeitet; Anforderungen, Scope, Betrieb und Abnahme erweitert. | Entwurf    |
| 0.1         | 08.09.2026 | Erstfassung des Fachkonzepts als Grundlage für Planung und Abnahme.                                     | Entwurf    |
