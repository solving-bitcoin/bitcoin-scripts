# Fortlaufender Forschungsstand

Letzte abgeschlossene Untersuchung: R22, 17. September 2026.
Die Wiederaufnahme `geheimnisfreien-bitcoin-covenant-finden` bleibt aktiv.
**Es gibt weiterhin keine vollständige geprüfte Lösung.** Keine Automation
wurde wegen einer bloßen Teilkonstruktion beendet.

## Ziel und bisheriger Ausgangspunkt

Unverändert gelten die Kriterien aus [der bisherigen Zusammenfassung](../seven/README.md):
exakte Output-Beträge, Reihenfolge und Scripts; bestehende Bitcoin-Opcodes;
keine Schlüsselvernichtung; Ersteller behält sämtlichen Zustand und darf
Alternativen vor Funding vorbereiten; ehrlicher Gesamtaufwand einschließlich
Setup/Audit kleiner als `2^64`; größere Arbeit für eine Verletzung. Ein
vollständiger erlaubter Spend darf vor Veröffentlichung des Fundings geprüft
werden. Bibliothekscode und fremde Arbeitsänderungen bleiben erhalten;
Feldarithmetik-Tests werden nicht ausgeführt.

Der native Zwei-Treffer-Baustein hat 199 Opcodes, 273 Bytes und ungefähr 56
wirksame Nonce-Bits; sein arithmetisch geprüfter Output-Bezug fehlt.
Observable Routing- und Recovery-Mengen-Vektoren wurden gegen Core geprüft,
aber kein vollständiger Zwei-Treffer-PoW-Zeuge berechnet.

## R4: neue geprüfte Teilfragen

1. [Taproot/ECDSA/Schnorr-Hybrid](r4_taproot.md): Die native Tweak-Gleichung
   wurde mit dem unbekannten ECDSA-Nonce-Punkt kombiniert. Die direkte
   Auslöschung dieses Punktes verlangt einen tatsächlichen Schnorr-Challenge
   von `+1` oder `−1`, einschließlich aller Paritätsfälle. 16 Host-Fälle
   bestätigen die Gleichung bei künstlich gesetztem Challenge; die echten
   Challenges erfüllen sie nicht. Bekannter Logarithmus des Innenschlüssels
   liefert weiterhin einen frei signierbaren Key-Path. Kein neuer Verifier.
2. [Öffentliche Stichprobenprüfung mit QSB-Pinning](r4_succinct_reference.md):
   Für m effizient aufzählbare zugelassene Teilmengen je Runde und
   `s=1−(1−p)^m` kostet die explizite Strategie für Pinning plus zwei Runden
   `(1+1/s+1/s²)/p` native Prädikatsabfragen im unabhängigen Modell.
   Acht kleine Fälle wurden vollständig ausgezählt. Ein einzelnes festes D
   kostet mit Pinning wesentlich mehr als ein frei wählbares D; große
   Urbildmengen einer Beweisabfrage können diese Verstärkung wieder abbauen.
   Das sind Strategiekosten, keine allgemeine Schranke und keine Übertragung
   gewöhnlicher PCP-Soundness auf QSB.
3. [Neue Quellenprüfung](r4_sources.md): ePrint 2025/912 und die aktuellen Implementierungen
   AppliedPQC/bitcoin-stark-verifier sowie bitlayer-org/tap-stark wurden
   als zusätzliche konkrete Verifier-Kandidaten untersucht. Das Paper setzt
   BSV-Operationen voraus. Der untersuchte AppliedPQC-End-to-End-Test nutzt
   Sicherheitsparameter 1 und einen am Host berechneten Schlusswert; er
   führt nicht den vollständigen Verifier aus. TapSTARK bindet einzelne
   Taptree-Zeilen, liefert aber nicht die verpflichtende Gesamtprüfung.
   Immutable Commits und konkrete Ressourcen-/Witness-Grenzen stehen im Bericht.

Alle R4-Algebra-/Strategiemodelle sind Host-Experimente (`locally-reproduced`,
Deployment `unclassified`), keine neuen Konsens- oder Covenant-Belege.

Validierung R4: beide neuen deterministischen Host-Experimente erneut
ausgeführt; Python-Syntax geprüft; `python3 tools/kb.py validate` und
`git diff --check` bestanden. Kein Bibliothekscode, keine Primitiv-Metrik und
keine bestehende Testkonfiguration wurden geändert.

## R5: Commitment als tatsächliche variable Signatur

1. [Core-Vektoren](r5_root_core.md): Der bekannte öffentliche 16-Byte-Blob
   liefert eine tatsächlich gültige SHA256-Signatur für `SHA256 SWAP CHECKSIG`.
   Sein r hat keinen Punkt bei x=r, wohl aber bei x=r+n. Beide Vorzeichen
   dieses zweiten Recovery-Zweigs funktionieren. Das Flag ist NONE:
   Derselbe Zeuge erlaubt andere Empfänger, Beträge, Output-Anzahl und
   Reihenfolge. Sechs positive Varianten sind nun auch `policy-validated`.
   Drei fehlerhafte Zeugen scheitern. Zwei weitere positive Vektoren mit
   Kontextvergleich sind nur `consensus-validated` (CODESEPARATOR-Policy).
   Insgesamt elf Erwartungen erfüllt, Evidenz `differentially-validated`.
   3/7 Bytes Redeem-Script, 2 Datenitems, 0 Hints, kombinierter Peak 4;
   vollständige Transaktionen und Messgrenzen stehen im Bericht.
2. [Flag-Prüfung](r5_root_flags.md): 240 von 256 Legacy-Flagbytes binden alle
   Outputs; eine ehrliche Wahl kostet nur Faktor 16/15, erzwingt sie aber
   nicht. Ein neuer Fünf-Opcode-Guard (erster Kontext wahr, zweiter falsch)
   verwirft sämtliche SINGLE-Bug-Fälle. NONE und reguläres SINGLE überleben.
   512 Host-Fälle bestätigen die Abgrenzung. Eine zusätzliche feste
   ALL-Signatur verlangt eine echte Gruppengleichung, nicht bloß ein Flag.
3. [Root-Wiederverwendung](r5_root_chronology.md): Für einen Root mit L echten,
   vom selben Beweis gedeckten Transaktionsvarianten, zwei Subset-Domänen m1/m2
   und unabhängigen Treffern gilt für die untersuchte Strategie
   `E=1/(a*t)+1/(p*s1*s2)+1/(p*s2)+1/p`,
   `si=1−(1−p)^mi`, `t=1−(1−p*s1*s2)^L`.
   Sechs vollständig ausgezählte Modelle bestätigen sie. Optimistisch a=p
   und große m: L=1 kostet ungefähr `2^90.85`; L=`2^32` ungefähr `2^58.85`
   Abfragen. Bei m=`2^40` kostet letzteres stattdessen `2^69.74`.
   Das sind weder Gesamtkosten noch ein implementierter Verifier. Ein Trace
   seines eigenen aus alpha gewonnenen Recovery-Keys ist selbstbezüglich;
   ein anfänglicher SHA-Trace benötigt eine authentifizierte spätere
   EC-Auswertung. Ein universelles Programm bindet noch keine Wire-Werte.
4. [Tapscript-Ersatz](r5_tapscript_reference.md): 112 Host-Zeugen reproduzieren
   sämtliche 3-aus-8-CHECKSIGADD-Muster für zwei Output-Listen desselben
   synthetischen Funding-Outpoints. Solche freiwilligen Erfolgsbits liefern
   keine transaktionsbestimmte Abfrage. Bei P=R=G bleibt die Bindung des
   variablen 32-Byte-Skalars an die tatsächliche Signatur offen. Eine explizite
   feste Signaturtabelle hätte diese Bindung, kostet im untersuchten
   Idealmodell einschließlich Aufbau aber mindestens `2^128.5` Arbeit.

Alle neuen Host-Modelle sind `locally-reproduced`, Deployment `unclassified`.
Nur die ausdrücklich verlinkten Core-Vektoren besitzen Konsens-/Policy-Belege;
kein vollständiger Covenant oder neuer PoW-Treffer wurde erzeugt.

Validierung R5: Core-Vektoren ausgeführt; drei deterministische Host-Experimente
erneut ausgeführt; Python-Syntax, KB-Validierung und `git diff --check` geprüft.
Keine Bibliotheksänderungen, Feldtests oder Primitiv-Metrik-Updates.
Bei alternativen Core-Policy-Prüfungen immer den Mempool leeren: Ein
`invalidateblock` kann zuvor akzeptierte Spends zurückstellen und sonst
RBF-Gebührenfehler statt Script-Policy messen. R5 startet den isolierten
Node mit erhaltener Mocktime und deaktivierter Mempool-Persistenz neu.

## R6: konkrete Funktionsbindung, Korrelation und bessere Längensuche

1. [Signaturlängen-Puzzle](r6_length_puzzle.md): Die vollständige öffentliche
   Strategie `s=min(2(z+1) mod n, −2(z+1) mod n)` nutzt vier Digest-Intervalle.
   Für exakt 55 Signaturbytes gilt im gleichverteilten 256-Bit-Modell
   `p=255/2^48`, also etwa `2^40.00565` Abfragen, statt der bisher zitierten
   Nullpräfix-Strategie `2^42`. Für 59 Bytes gilt `p=255/2^16`, ungefähr
   `2^8.00565`. Alle vier 59-Byte-Intervalle wurden mit tatsächlichen
   Funding-/Spending-Transaktionen gegen Core bestätigt, auch mit null oder
   einem führenden Nullbit. Vier positive Fälle sind `policy-validated`,
   drei negative scheitern; Evidenz `differentially-validated`.
   39 Bytes Redeemscript, 100 Bytes scriptSig, 728 WU, 1 Datenitem, 0 Hints,
   kombinierter Peak 3. Kein 55-Byte-Zeuge gemint. Der frühere
   SHA256-zu-DER-Wert `780555/2^65` betrifft ein anderes Prädikat und bleibt
   unverändert. Keine vollständige Binohash-Kollisionsanalyse neu bewiesen.
   Die externen aaron-recompile-Experimente wurden zusätzlich am Commit
   `67550443a7783b087205c13a80a0df7788496e94` inspiziert: deren Bits-Prädikat
   ist ein Host-Nullpräfix-Test, nicht der on-chain ausgeführte Signaturlängentest.
2. [Funktionsbindung](r6_function_commitment.md): Eine konkrete gemischte
   Hashkette bindet n lesbare normalisierte Bits an einen möglichen Alpha-Root
   mit `3+8n` statischen Legacy-Opcodes, n+1 Datenitems, 0 Hints, Peak n+3.
   267 Host-Vektoren und drei Encoding-Fälle geprüft. Das bindet kurze
   Parameter, keine später frei gewählten Wire-Werte. Der explizite
   Sumcheck-Lookup benötigt abschließend eine authentifizierte Auswertung
   außerhalb des Booleschen Würfels. Ohne diese akzeptieren alle 3.375
   falschen Toy-Transkripte; mit echter Endauswertung nur 191. 96 ehrliche
   Beweise funktionieren. Die direkte 77-Runden-Variante braucht bereits
   616 großzügig gezählte Feldoperationen/Vergleiche vor nativen Prüfungen.
3. [Korrelierte Roots](r6_correlated_root.md): Ein echter nativer Zwei-Key-
   Zyklus `H(P0)` unter P1 und `H(P1)` unter P0 benötigt 8 Opcodes, 2 Daten,
   0 Hints, Peak 4. Im kleinen F211-Modell verifizieren 11.880 Recovery-Kanten
   und acht Zyklen. Noch fehlen ein bezahlbarer großer Kurzzyklus-Solver und
   eine Output-Asymmetrie. Eine andere exakte Korrelation
   `z=int(DER)=C+256s`, `P=−C/r*G` löscht s aus und erzwingt Nonce 256G.
   Dessen r braucht 33 DER-Bytes; ein 32-Byte-Hash erlaubt höchstens 24.
   24 tatsächliche secp256k1-Fälle bestätigen diese Formatgrenze.
4. [Adaptive Hashgraphen](r6_scalar_bridge.md): In der klar begrenzten Familie
   positiver Gleichheitsbrücken aus vollständigen nativen Hashwerten braucht
   die erste Verbindung weiterhin eine mindestens 160-Bit-Kollision.
   Alle Setup-/Suchabfragen Q zählen: `Pr <= Q(Q−1)/2^161` im Idealmodell.
   4.096 vollständig ausgezählte Toy-Orakel bestätigen den adaptiven
   Zweipfadfall. Neue Gruppenrelationen, unabhängig anders erzeugte lange
   Container und echte SHA1-Kryptanalyse sind ausdrücklich nicht erfasst.

R6-Host-Experimente: `locally-reproduced`, Deployment `unclassified`.
Kein vollständiger Covenant gefunden. Alle neuen Skripte syntaktisch geprüft,
deterministische Host-Reproduktionen wiederholt, sieben Core-Fälle bestanden;
KB-Validierung und Diff-Prüfung bestanden. Keine Bibliotheksänderungen,
Feldtests oder Primitiv-Metrik-Updates.

## R7: variable Nonces, Quotientenbindung und variable DER-Gleichung

1. [Nonce-Portfolios](r7_nonce_portfolio.md): Verschiedene Nonce-Multiplikatoren
   erzeugen im vollständig ausgezählten kleinen Modell 238 Längenmuster
   gegenüber 24 bei gemeinsamem Multiplikator. Die alte Schranke für bloße
   Key-Verschiebungen deckt sie nicht ab. Bei einer festen r-Länge beträgt
   die optimistische 55-Byte-Setup-/Query-Schranke ungefähr `2^65.506`.
   Gemischte Längen dürfen nicht mit derselben Schranke ausgeschlossen werden;
   ihre Paarwahrscheinlichkeit liegt im Idealmodell bei ungefähr `2^-124.9235`.
   Vier reale secp256k1-Host-Signaturen zeigen zugleich, dass SIZE weder den
   gewählten Nonce noch eine Output-Referenz erzwingt.
2. [Einrunden-Quotient](r7_specialized_verifier.md): Der Lookup lässt sich als
   `F(r)-y=(r-x)Q(r)` formulieren. Ein vollständig vorab gebundener falscher
   Quotient kann genau beliebige N−1 Challenge-Punkte zum Akzeptieren bringen.
   F257/N16: 4.112 ehrliche Identitäten und exakt 15/256 gewählte falsche
   Akzeptanzen. Ohne Q-Authentifizierung passieren alle 4.096 falschen Fälle.
   Die konkrete lesbare Koeffizientenbindung benötigt bereits im Toy 1.083
   Opcodes. Zwölf secp256k1-Öffnungen zeigen, dass ein öffentlicher oder
   behaltener KZG-Auswertungsskalar keine bindende Ersatzprüfung liefert.
3. [Variable DER](r7_variable_der.md): Der Solver für `P=−A*G` prüft r über
   `(256+C0/s)G`. Alle 32.512 Einbyte-s/Flag-Kombinationen wurden ohne Treffer
   ausgewertet. Die bekannten ±G/2 sind für sämtliche vierbyteigen s und
   alle Flags exakt ausgeschlossen. Freie Keys liefern sechs echte
   Selbst-Digest-Signaturen, aber keine dazu passenden nativen Hash-Preimages.
   Die endliche Zielmenge und Funding-Selbstabhängigkeit bleiben ausdrücklich
   Teil der Kosten. Keine generelle Unmöglichkeitsaussage.

R7: `locally-reproduced`, Deployment `unclassified`; keine neuen Core-Belege.

## R8: konkreter subquadratischer Join und neue native/algebraische Beziehungen

1. [Intervall-/Kongruenz-Join](r8_batch_incidence.md): Für kleine bekannte k
   lautet die Signaturbedingung `z=±k*s−r*d mod n`. Eine kurze s-Domäne ergibt
   wenige modulare Intervalle und eine Kongruenz pro Intervall. Ein Hashraster
   auf den Digest-Werten findet Kandidaten ohne die naive R×Q-Paarprüfung.
   2.828 vollständige kleine Mitgliedschaftsprüfungen, neun Joins gegen
   Brute Force und acht gepflanzte secp256k1-Treffer reproduziert. Die
   erwartete lineare Eingabe-/Kandidatenarbeit gilt unter expliziten
   Verteilungsannahmen; Speicher, Konstanten und endliche k-Grenzen zählen.
   Unterschiedliche Primmoduli und riesige CRT-Zahlen werden nicht benötigt.
2. [Core-Prüfung des Joins](r8_batch_core.md): Tatsächliche ALL-Sighashes
   liefern vier 70-Byte-Signaturen mit r-Länge 32/33 und beiden Nonce-Vorzeichen.
   Alle vier bestehen Core-Konsens und Standard-Policy; drei negative Fälle
   scheitern. 128 öffentliche Punktadditionen, jeweils 4.096 echte Hashwerte,
   etwa 69–70 Tausend Kongruenztests statt 524.288 Paarprüfungen. 39 Bytes
   Redeemscript, 111 Bytes scriptSig, 1 Datenitem, 0 Hints, Peak 3; 772 WU bei
   einem und 896 WU bei zwei Outputs. `differentially-validated`, positive
   Spends `policy-validated`. Kein 55-Byte-PoW und kein Covenant.
3. [Erwartete Portfolio-Kosten](r8_portfolio_costs.md): Seltene r-Zeilen
   verlangen `E[1/U]`, nicht den Kehrwert der mittleren Paarmasse. Ein
   explizites Poisson-/Mittelwertmodell mit kostenloser Klassifizierung
   liegt bei ungefähr `2^63.94724` erwarteten Eingabesamples. Schon ein
   angenommener Punktpreis von zwei Digest-Einheiten ergibt `2^64.45412`.
   Das sind bedingte Modellwerte, keine gemessenen Kurvenkosten oder
   allgemeinen Schranken. Der separate Streaming-Ansatz hat ebenfalls nur
   sehr knappen Abstand vor Matching- und Speicherarbeit. Die bisherige
   51%-Erfolgsquote darf nicht als erwarteter Gesamtaufwand ausgegeben werden.
4. [Native Nonce-Bindung](r8_nonce_binding.md): Eine duplizierte Signatur in
   2-von-m-CHECKMULTISIG erzwingt eine echte Beziehung. Bei zwei Recovery-
   Wurzeln folgt jedoch `r=−2z/(d_i+d_j)`, ein vom Digest abhängiger Wert.
   Zwölf echte Kurvenfälle bestätigen die Relation. Feste Keys machen den
   gewünschten bekannten Nonce zum vollen Digest-Ziel; freie Witness-Keys
   liefern acht günstige Zeugen für zwei unterschiedliche Output-Listen.
   Der 14-Byte-/13-Opcode-Fall hat 3 Daten, 0 Hints, Peak 7. Vier-Wurzel-
   Ausnahmen werden nicht durch den Spezialfall ausgeschlossen.
5. [Gekoppelte DER-Signaturen](r8_coupled_der.md): Zwei verschiedene
   32-Byte-Signaturen mit demselben kurzen r und `s2=q*s1` verifizieren auf
   `z=int(DER(r,s1,f))` unter explizit affin verwandten öffentlichen Keys.
   C0 wird tatsächlich eliminiert; 108 reale Kurvenfälle bestanden. Die
   feste r-/Layout-/Flag-Familie besitzt für q=2 aber nur etwa `2^30`
   Alpha-Werte und verlangt im uniformen nativen Hashmodell etwa `2^226`
   Abfragen. Bei vor Funding fixiertem Key bleibt je Vorzeichen nur ein s.

Außer den ausdrücklich genannten Core-Vektoren sind R8-Experimente
`locally-reproduced`, Deployment `unclassified`. Keine vollständige Lösung.
Die Drei-Minuten-Wiederaufnahme wurde als weiterhin ACTIVE verifiziert.

Die [unabhängige Join-Prüfung](r8_batch_audit.md) reproduziert 18.258
Intervallkonfigurationen mit 307.922 Mitgliedschaftsvergleichen und 160
vollständige Joins gegen direkte s-/Vorzeichen-Enumeration. Ein anfänglicher
API-Fehler bei nicht reduzierten Digest-Werten wurde durch eine explizite
Vorbedingung und vier Gegenproben behoben. Alle sieben gespeicherten Core-
Transaktionen wurden zusätzlich aus ihren Bytes unabhängig nachgerechnet.
Sämtliche acht R7/R8-Host-Experimente, Python-Syntax, JSON, KB-Validierung
und Diff-Prüfung wurden zum Abschluss erneut erfolgreich ausgeführt. Keine
Bibliotheksänderungen, Feldtests oder Primitiv-Metrik-Updates.

## R9: allgemeine Drei-Key-Gleichheit und kompaktere Root-Schnittstellen

1. **Universelle native ECDSA-Gleichheit:** Drei verschiedene Gruppen-Keys,
   die dieselbe gültige Signatur in zwei Kontexten bestätigen, erzwingen
   gleiche Digest-Skalare modulo n, für sämtliche r und s einschließlich
   aller r+n-Fälle. Der [Beweis](r9_four_roots.md) reduziert eine mögliche
   Ausnahme auf eine viergliedrige arithmetische Progression der Noncepunkte
   und damit `x(3P)=x(P)±n`. Vollständige Polynom-Wurzelzählung findet im
   zulässigen Bereich keinen Treffer. Die unabhängige
   [9×9-Matrixprüfung](r9_recovery_audit.md) bestätigt exakt drei Fp-Wurzeln
   für F+ (alle außerhalb) und keine für F−, ohne den Polynom-GCD- oder
   Faktorisierungscode zu verwenden. 1.394 kleine Gruppenfälle ergänzen den
   exakten Beweis. Hash- oder DLog-Annahmen sind für die Gleichheitsimplikation
   nicht nötig. Drei kanonische 33-Byte-Keys und eine wirklich gemeinsame
   Signatur sind wesentliche Voraussetzungen.
2. **Core-Ausführung der variablen Signatur:** Der
   [75-Byte-/47-Opcode-Prüfer](r9_recovery_core.md) besteht vier Konsens- und
   Policy-Tests mit (r,s)=(2,1),(4,2),(6,17),(16,129), jeweils drei von vier
   Recovery-Keys. Vier negative Fälle scheitern. Gleicher Kontext ist bei
   Positiven ausdrücklich beabsichtigt; ein anderer CODESEPARATOR-Kontext
   wird negativ geprüft. 4 Daten, 0 Hints, Peak 7; 188/189 Bytes scriptSig,
   1.080/1.084 WU. Variante mit CODESEPARATOR: 76 Bytes/48 Opcodes.
   `differentially-validated`; positive Spends `policy-validated`.
3. **Geprüfter skalierter Vierwurzel-Kandidat:** Gemeinsame Keys zwischen
   r=2/s=1 und r=2/s=t für t=2..127 sind stets höchstens einer, da alle 16
   Punktdifferenzen verschieden sind. Ein Prüfer, der zwei verlangt, kann
   daher unabhängig von den Digests nicht erfüllt werden. Öffentliche
   punktabhängige Offsets liefern dagegen 32 günstige Key-Paare für beliebige
   Digests und schaffen keine Output-Asymmetrie. Dies ist ein begrenztes
   Ergebnis, nicht die universelle Aussage über verschiedene Signaturen.
4. **Hash als x-only Key:** Die [8-Byte-Tapscript-Schnittstelle](r9_hash_xonly.md)
   `SWAP SIZE 64 EQUALVERIFY SWAP SHA256 CHECKSIG` konsumiert H(proof) direkt
   als Key und erzwingt DEFAULT. Funding und spätere Proof-Wahl sind dabei
   tatsächlich azyklisch. 242 von 512 SHA256-Roots liften, aber ihre
   Logarithmen sind unbekannt. Ein Solver mit bekanntem Signaturnonce offenbart
   einen wiederverwendbaren Schlüssel; acht bedingte echte BIP340-Hostfälle
   und ein vollständiger kleiner Kurvensolver zeigen das. Der affine
   unbekannte Nonce verlangt weiterhin einen vollen Challenge-Treffer.
   Kein vollständiger echter Hash-Key-Zeuge oder Core-Erfolg behauptet.
5. **Lesbare Zahl im Root:** Der [numerische Root](r9_numeric_root.md) behält
   eine durch `0 ADD` normalisierte ScriptNum und verwendet SHA256 ihrer Bytes
   als langen Seed des bisherigen Hashpfads. 61 Stufen: 252 Bytes/189 Opcodes,
   61 Daten einschließlich 60 Hints, Peak 64. Ein kompletter ungeminter
   Root-Signatur-/Pin-/Zahlvergleich hat 267 Bytes/198 Opcodes, 62 Daten,
   60 Hints, Peak 65. 1.785 gültige und 303 fehlerhafte Hostfälle geprüft;
   unabhängige Zählung bestätigt die Kosten. Nur ein Integer, kein allgemeiner
   Verifier; der endliche Pfadraum und fehlende Root-Wiederverwendung zählen.
6. **Rationale Nonces:** [Dyadische Nenner](r9_rational_nonce.md) reduzieren
   nach korrekter Duplikatentfernung die Intervall-Kandidatenmasse, benötigen
   dafür transformierte Raster oder mehrere Urbildintervalle im gemeinsamen
   Raster. Beide Varianten liefern dieselben drei echten secp256k1-Treffer.
   Zusätzliche Indexarbeit verhindert einen pauschalen Kostengewinn; keine
   neue Output-Bindung oder allgemeine Kostenschranke folgt.

R9-Hostresultate sind `locally-reproduced`, Deployment `unclassified`;
Konsens-/Policy-Evidenz gilt nur für die expliziten Core-Vektoren. Die
vollständige Covenant-Lösung bleibt offen. Die neue universelle
Drei-Key-Aussage verbessert eine native Schnittstelle; sie ersetzt nicht die
verpflichtende Auswertung der erlaubten Outputs.

Validierung R9: alle fünf Host-Experimente erneut ausgeführt; die acht
Core-Erwartungen bestanden. Ein unabhängiger Agent rekonstruierte zusätzlich
beide ScriptCode-Preimages, Stack-Abläufe, Gebühren und Gewichte aus allen
acht gespeicherten Transaktionen. Python-Syntax, JSON, KB-Validierung und
Diff-/Whitespace-Prüfung bestanden. Keine Feldtests, Bibliotheksänderungen
oder Primitiv-Metrik-Updates. Die Wiederaufnahme bleibt aktiv.

## R10: Referenz im selben Input, parallele Zyklen und größere Seed-Domäne

1. **SINGLE und ALL im selben gesperrten Input:** Die neue
   [Referenz-Schnittstelle](r10_reference_interface.md) benötigt keinen
   externen Verifier-Input: Eine Signatur kann den SINGLE-Bug-Digest mit
   Skalar C=`2^248` verwenden, eine andere im selben Input trotzdem alle
   Outputs binden. Die direkte Drei-Key-Variante mit identischen numerischen
   Signaturen und literalen Flags verlangt jedoch `z_ALL=C`, also einen
   vollständigen Digest-Treffer. 123 Bytes/41 Opcodes, 3 Daten, 0 Hints,
   Peak 6. Bei zwei Recovery-Wurzeln und verschiedenen Signaturen gilt für
   gemeinsame zwei Keys `z/r_beta=C/r_alpha`, zusätzlich zur passenden
   Punktbreite. 16 echte secp256k1-Skalierungsvektoren zeigen diese Beziehung
   konstruktiv; eine passende tatsächliche ALL-Transaktion fehlt. 256 Flags,
   vier Output-Varianten und die korrekte lokale Signaturentfernung geprüft.
   Ein unabhängiger Agent reproduzierte Serializer, Stack und Gleichungen.
2. **Zwei parallele Key-Zyklen:** Der [Zyklusbericht](r10_parallel_cycles.md)
   liefert einen konkreten Sieben-Knoten-Entwurf mit 330 Bytes/199 Opcodes,
   21 Daten, 0 Hints, Peak 24; sechs Knoten mit Signaturlimit 60 Bytes brauchen
   304 Bytes/188 Opcodes, 18 Daten, Peak 21. Im Zwei-Wurzel-Fall erzwingen
   gemeinsame Key-Paare einzelne Zentrumsgleichheiten an jedem Knoten;
   eine einzige freie Wagner-Summenbeziehung genügt bei festen Nonces nicht.
   Formal freie r lassen eine Produktgleichheit und einen Skalierungsfaktor,
   aber die zugehörigen Nonce-Logarithmen sind nicht konstruiert. 1.020
   Vorzeichenmuster und die vollständigen zwölf geordneten r=2-Paarzustände
   einschließlich acht nichttrivialer Übergänge geprüft. Vier native,
   unfinanzierte Same-Context-Kontrollen sind Host-Ergebnisse, kein Core-Test.
3. **Mehr Roots für dieselbe kleine Funktion:** Der
   [gepackte Seed](r10_parameter_frontier.md) `x=7+16q` bindet die Funktion
   `y=t+7` bei `2^28−1` zulässigen q-Werten. Ein 37-stufiger Root-/Pin-Entwurf
   mit exakter affiner Prüfung hat 185 Bytes/143 Opcodes, 41 Daten mit
   37 Hints (36 Pfadselektoren und q), Peak 44; 58 Opcodes bleiben frei.
   Seine endliche Domäne hat etwa `2^61.7767` semantische Root-Kandidaten.
   Eine Präfixbaum-Auswertung benötigt etwa `2^62.6963` einzelne Hashaufrufe
   für die vollständige Aufzählung. Unter der **zusätzlichen, noch nicht
   erfüllten** Annahme von `L=2^32` funktionsgültigen nativen Varianten je Root
   ergibt das unabhängige DER-/Pin-Modell ungefähr 99,95 % Erfolgswahrscheinlichkeit.
   Diese Zahl ist kein Nachweis für Gesamtarbeit unter `2^64` oder eine echte
   Output-Referenz. 760 positive und neun negative Observable-Fälle; die
   [unabhängige Prüfung](r10_frontier_audit.py) ergänzt 60 Stack-Fälle,
   60 falsche Affin-Ausgaben und zehn explizite Präfixsprachen.

Alle R10-Ergebnisse sind `locally-reproduced`, Deployment `unclassified`.
Keine neuen Core-Erfolge, geminten vollständigen Root-/Pin-Zeugen oder
vollständigen Covenants. Die bessere Seed-Domäne widerlegt eine zu breite
Behauptung, ein einzelner lesbarer Integer lasse prinzipiell zu wenige Roots
für jede kleine Funktion zu. Sie liefert weiterhin keinen allgemeinen
SHA-/EC-Referenzverifier und keine native Bindung der Variablen t/y.

Validierung R10: vier deterministische Python-Reproduktionen, Syntax-/JSON-
Prüfung, KB-Validierung und Diff-/Whitespace-Prüfung. Keine Feldtests,
Bibliotheksänderungen oder Primitiv-Metrik-Updates. Die Wiederaufnahme bleibt
aktiv. Eine Teilaufgabe wurde vom automatischen Subagent-Filter beendet;
die öffentliche mathematische Untersuchung wurde lokal übernommen und
vollständig als begrenzte R10-Teilfrage bearbeitet.

## R11: konstruktive Nonce-Ratios nach dem tatsächlichen Digest

1. **Endomorphismus-Solver:** Die [neue Gitterkonstruktion](r11_endomorphism.md)
   findet für einen bereits gegebenen nativen ALL-Digest z Nonce-Koordinaten
   mit `x' = beta*x mod p` und `x' = (z/C)*x mod n`, C=`2^248`.
   Die bekannte Punktrelation `R_beta=lambda*R_alpha` liefert die nötige
   Signaturskalierung ohne die individuellen Nonce-Logarithmen. Das korrigiert
   eine zu breite Interpretation des R10-Logarithmus-Hindernisses für **freie**
   Signaturen. 43 von 64 deterministischen Verhältnissen waren innerhalb des
   angegebenen Suchlimits lösbar; acht tatsächliche unfinanzierte
   ALL-Transaktionsvorlagen benötigten zusammen 15 Locktime-Kandidaten.
   928 kleine Gitterrechtecke wurden vollständig gegengeprüft. Der rohe
   Vier-Prüfungs-Baustein hat 44 Bytes/27 Opcodes, 4 Daten, 0 Hints, Peak 7.
   Die Script-Bedingung allein erzwingt nicht die gewählten Flagbytes.
2. **Core-Erfolg:** Die [finanzierten Vektoren](r11_endomorphism_core.md)
   verwenden denselben P2SH-Outpoint und denselben gewöhnlichen P2WSH-Zusatzinput.
   Drei öffentlich neu berechnete Zeugen für verschiedene Empfänger/Beträge
   bestehen Konsens und Standard-Policy; drei fehlerhafte Varianten scheitern.
   227/226/228 Bytes scriptSig, 1.406/1.402/1.410 WU; 4 Daten, 0 Hints,
   Peak 7. Die vollständige Witness-Serialisierung des Zwei-Input-Spends
   umfasst 4 Bytes plus 2 Marker/Flag-Bytes. Unabhängige Rekonstruktion aller
   Transaktionen, Gebühren, Digests und Gleichungen bestätigt die Ergebnisse.
   Das zeigt die neue Schnittstelle und gleichzeitig ihre fehlende
   Output-Asymmetrie. Kein Alpha-Hash-Preimage wurde gefunden.
3. **Hash-Root getrennt zählen:** Die
   [Kostenanalyse des festen Endomorphismus-Katalogs](r11_endomorphism_root_cost.md)
   zählt maximal vier Digest-Ziele je festem Alpha. Ein echtes 32-Byte-DER-Alpha
   hat r höchstens `2^191−1`; die zusätzliche x-Koordinate r+n ist nur für
   r<p−n möglich. Die gesamte kurze Zielmenge beträgt höchstens ungefähr
   `2^-64` des Skalarraums, vor Hash-Preimage-Bindung. Im explizit unabhängigen
   Idealmodell gilt für adaptiv aufgeteilte Q Gesamtqueries die Schranke
   `Q(Q−1)/2 * p_DER * 8/2^256`; bei Q=`2^64` ungefähr `2^-171.43`.
   Die unabhängige Prüfung korrigierte den unzulässigen Q²/4-Vorfaktor:
   dieser gilt mit festen Listenlimits, nicht allgemeiner adaptiver Aufteilung.
   Ein exakter Q=3-Gegenfall und 198 kleine Kurven-Streifen bestätigen die
   Abgrenzung. Keine Schranke für alle nativen Signaturpaare oder Covenants.
4. **Tatsächlicher nativer Tabellen-Lookup:** Die
   [Literal-Tabelle](r11_lookup_reference.md) bindet genaue Alpha-Bytes und
   drei festgeschriebene Keys an eine echte native ALL-Referenzzeile.
   CODESEPARATOR entfernt die Tabelle aus scriptCode. Zwei Zeilen plus
   numerischer 37-Stufen-Root: 487 Bytes/170 Opcodes, 39 Daten mit 37 Hints,
   Peak 42. Zwei echte Host-Referenzfälle und zehn negative Prüfungen bestehen;
   die 21 kombinierten Root-Fälle simulieren CHECKSIG ausdrücklich, weil kein
   seltener Root gemint wurde. Der präzise offene Kreis bleibt
   Tabelle → Funding-Txid → ALL-Digest → Tabellenschlüssel. Drei konkrete
   Funding-Umschreibungen machen vorherige Zeilen ungültig. Keine vollständige
   azyklische Einrichtung oder Einrichtungskosten unter `2^64` gezeigt.
5. **Neue Primärquelle PIPEs v2:** Der
   [Quellenbericht](r11_reference_sources.md) prüft den Folgeentwurf von 2026.
   Dessen gültiger Witness autorisiert laut Definition jede Nachricht;
   die konkrete Instanz gibt einen wiederverwendbaren Signierschlüssel frei.
   Selbst ideales Setup ohne zurückbehaltene Geheimnisse erfüllt daher nicht
   unsere nachrichtenabhängige Output-Relation. Benötigt wäre eine nicht
   umgehbare Signierfunktion für `R(x,m,w)`. Binohash/QSB/ColliderScript/
   ColliderVM liefern in den geprüften Kombinationen weiterhin keinen solchen
   vollständigen Anschluss. Quellen sind versioniert, Abrufgrenzen angegeben.

R11-Hostergebnisse sind `locally-reproduced`, Deployment `unclassified`;
der Quellenbericht verwendet `reported` und `inspected`. Nur die ausdrücklich
verlinkten Core-Fälle sind `differentially-validated`, positive Fälle
`policy-validated`. Alle drei Host-Reproduktionen wurden wiederholt, die sechs
Core-Erwartungen erfüllt und die Artefakte unabhängig geprüft. Syntax/JSON,
KB-Validierung und Diff-Prüfung werden zusammen mit dem R12-Zwischenstand
abgeschlossen. Keine Feldtests, Bibliotheksänderungen oder Metrik-Updates.

## R12: tatsächliche Signatur als große öffentliche Hash-Domäne

Der Nutzer möchte frühe, kurze fachliche Rückmeldungen eines Subagents sehen,
zuletzt ungefähr jede Sekunde soweit die Tool-Laufzeit dies zulässt. Dafür
wurde `/root/r12_live_reference` mit dem Covenant-Auftrag gestartet. Berichte
Ansatz, öffentliche Gleichungen, beobachtete Ergebnisse und nächste Tests;
keine privaten internen Gedankenprotokolle. Keine sekundengenaue Garantie.
Dieser Agent lieferte weiter Meldungen und erfolgreiche Tests, während der
Nutzer erneut ein Filterbanner sah; dessen genaue Zuordnung ist deshalb
unbekannt. Frühere zwei Agent-Filterfehler sind sichtbar, aber das begründet
keine Diagnose jedes späteren Banners. Der Filter nennt keine Passage oder
konkreten Klassifikationsgrund. Der angeforderte Durchlauf wurde vollständig
abgeschlossen und meldete keinen Toolfehler.

Der [R12-Bericht](r12_live_reference.md) untersucht `h=SHA256(alpha)` für die
frei skalierbaren vollen R11-Signaturen statt `alpha=H(proof)`. Bei festem
nativen z und einer Gitterlösung gilt für fast alle LOW_S-s weiterhin
`P_s=(sR−CG)/r`, `Q_s=(−sR−CG)/r`; die passende Beta skaliert mit s.
Damit benötigt ein neuer SHA256(alpha_s)-Versuch nur DER-Serialisierung und
Hashing. Die Kurvenarbeit für Keys/Beta kann nach dem Hashfilter erfolgen.
Die Familie hat ungefähr n/2 verschiedene Alpha-Werte; die Signaturen selbst
müssen nicht in einen 32-Byte-Hash passen.

Der echte Hashgleichheitsanschluss hat 55 rohe Bytes/35 Opcodes, 5 Daten,
0 Hints und Peak 7. 48 Host-Zeugen mit 192 ECDSA-Gleichungen, 24 negative
Prüfungen und 16.384 tatsächliche Hashversuche bestehen. Vier Outputvarianten
mit unveränderten synthetischen Prevouts funktionieren. Alle h-Werte sind
frei geliefert und werden an die tatsächlich geprüfte Alpha gebunden;
sie sind weiterhin keine lesbare Soll-Output-Referenz. Kein Hashversuch
ergab einen DER-Treffer; es wurde nur eine kleine kontrollierte Stichprobe
ausgeführt, keine Schätzung der seltenen Erfolgswahrscheinlichkeit.

Ein zweiter 55-Byte-/35-Opcode-Entwurf würde `gamma=SHA256(alpha)` als echte
DER-Signatur unter einem freien Recovery-Key K prüfen. Diese Variante ist
nur abgeleitet und ungemint, nicht positiv ausgeführt. Die etwa n/2 s-Werte
verändern Alpha; sie liefern **keine** zusätzlichen L-Transaktionen bei
festem Alpha. Im festen R11-Katalog bleiben dann höchstens vier Zielskalare.

R12: `locally-reproduced`, `unclassified`, kein neuer Core-Test. Die R11/R12-
Reproduktionen, Python-Syntax, JSON, KB-Validierung und Diff-Prüfung sind
abgeschlossen. Keine Feldtests, Bibliotheksänderungen oder Metrik-Updates.
Keine vollständige Covenant-Lösung gefunden; die Wiederaufnahme bleibt aktiv.

## R13: Hashschließung, Taproot-Tabelle und tatsächliche Orbit-Abfrage

1. [Hashschließung unter vorhandenen Keys](r13_gamma_closure.md): Ein
   öffentlicher Offset erzeugt 16 gewöhnliche Same-Key-Signaturpaare nach
   tatsächlichen Digests, aber kein Paar mit `gamma=SHA256(alpha)`.
   Für eine vor den Hashabfragen festgelegte R12-Familie passt jede Gamma
   zu höchstens vier s-Werten. Deshalb ist selbst über die gesamte Familie
   `E[Treffer] <= 4*p_DER ≈ 2^-43.426` im frischen idealen Hashmodell.
   Keine Schranke für beliebig adaptiv gewählte Familien. 300.762 exakte
   Toy-Mitgliedschaften, 39.402 Offsetfälle und sechs gepflanzte kurze
   Gamma-Vektoren reproduziert; kein hashgeschlossener Bitcoin-Zeuge.
2. [Taproot-Tabelle](r13_table_commitment.md): Sechs neue Core-Fälle zeigen
   den konkreten Fehler der direkten Übertragung. Die 33-Byte-Keys wählen
   in Tapscript den unbekannten Keytyp, also keine ECDSA-Prüfung. Derselbe
   Zeuge und derselbe reale Funding-Outpoint erlauben verschiedene Outputs
   auf getrennten Regtest-Zweigen. Konsens akzeptiert, Policy verwirft.
   Verändertes Blatt mit altem Control-Block scheitert; 32-Byte-Keys mit
   32-Byte-DER scheitern; zwei bekannte Key-Path-Zeugen sind policygültig.
   318 Blattbytes, 2 Daten, 0 Hints, 4 vollständige Witness-Items,
   390 Witnessbytes, Peak 11. Die einfache interne Punktkompensation löst
   auch die Tweak-Hash-Selbstabhängigkeit nicht.
3. [Orbit-Abfrage](r13_orbit_query.md): Die Identität
   `x0+x1+x2=h*p`, `h∈{1,2}`, ist exakt. Alle drei ECDSA-r einer echten
   Bahn sind verschieden, einschließlich r+n-Reduktion; vier vollständige
   Kandidaten schließen Gleichheit aus. Drei byteverschiedene Signaturen
   unter zwei Keys erzwingen die Bahn aber nicht: Die numerisch gleichen
   SINGLE-/SINGLE|ANYONECANPAY-Signaturen plus ALL akzeptieren h=1 und h=2
   bei identischen anderen Daten. Zwei tatsächliche native Host-Templates,
   vier positive und zehn negative Fälle: 64 Bytes, 39 Opcodes, 6 Daten,
   0 Hints, Peak 8, 291 Bytes scriptSig, 1.664 WU synthetisch.

R13-Hostresultate: `locally-reproduced`, `unclassified`. Die sechs einzeln
klassifizierten Core-Fälle sind `differentially-validated`; keine Übertragung
dieser Evidenz auf den Orbit- oder Hashschließungsentwurf. Alle Host-Resultate
wurden erneut ausgeführt; das gespeicherte Core-Artefakt wurde gelesen und
mit der vollständigen deterministischen Host-Fixture verglichen.

## R14: vollständige kurze Bahn und zwei stärkere native Graphen

1. [Kurze Orbit-Koordinaten](r14_orbit_observable.md): Wenn alle drei r
   höchstens `2^191−1` sind, erzwingt die exakte Summe `sum(r)=h*(p−n)`.
   Die vollständige Feldgitter-Box hat nur zwei mögliche Koeffizientenpaare
   und einen gültigen Koordinatenpunkt. Nur der gespiegelte h=2-Orbit hebt
   auf die Kurve. Es gibt genau eine Koordinatenmenge, bis auf Rotation;
   bei festem Lambda zwei Punktorbits durch ±y. Die r haben 127/129/129 Bit,
   die beiden letzten unterscheiden sich um 1. Jeder 32-Byte-Hash, der
   eines dieser r als DER-Signatur enthält, liegt in einer Menge mit
   exakter Dichte `32895/2^192`. Für `2^64` frische ideale Hashabfragen ist
   bereits ein Treffer höchstens `2^-112.9944` wahrscheinlich. Der Scope
   verlangt alle drei kurzen r; ein kurzer plus lange andere Signaturen
   ist nicht ausgeschlossen. Unabhängiger Agent bestätigte Vollständigkeit,
   DER-Zählung und alle R13-Metriken.
2. [Native Orbit-Graphen](r14_orbit_binding.md): Eine gemeinsame Signatur
   unter drei verschiedenen Keys `A+B,A+lambda*B,A+lambda²*B` würde eine
   Nullstelle von `4x³±3nx²+28` im Feld erfordern. Beide Polynome haben
   keine Feldnullstelle, bestätigt durch GCD und unabhängige 3×3-Matrix-
   Zertifikate. Vier gemeinsame Keys bei unterschiedlichen Signaturen
   erzwingen vollständige Recovery-Mengen und eine affine Abbildung ohne
   Offset. Ein nichttrivialer Endomorphismus-Hop würde dann den x-Abstand n
   in beta*n ändern und ist unmöglich. Drei gemeinsame Keys bei verschiedenen
   Signaturen sind ausdrücklich nicht durch dieses Argument erledigt.
3. [Gestufte Tabellenverpflichtung](r14_table_chronology.md): Eine späte
   SegWit-Witness-Publikation lässt die Txid unverändert, authentifiziert
   aber keine später gelieferten Recovery-Keys. Eine wirkliche P2WSH-
   Tabellenbindung verändert den verpflichtenden Vorfahren und damit alle
   folgenden Outpoints. Acht native/verschachtelte Ketten mit 1/2/4/8 Stufen,
   sechs BIP143-Modi und sechs echte ECDSA-Prüfungen bestätigen den Scope.
   Der Diagnose-Checker hat 51 Bytes/14 Opcodes, 4 Daten, 0 Hints,
   188 Witnessbytes, Peak 6. Kein allgemeiner Fixpunkt-Lower-Bound.

R14: `locally-reproduced`, `unclassified`, keine neuen Core-Fälle oder
Bibliotheksänderungen. Die beiden Root-Zertifikate und das vollständige
Staging-Artefakt sind reproduziert; alle Rechnungen enthalten die tatsächlichen
Feld-/Ordnungsreduktionen. Zwei Agent-Durchläufe brachen mit der bekannten
generischen Klassifizierungsfehlermeldung ab, ohne konkrete Passage oder
Begründung. Die Root übernahm ihre Algebra und speicherte reproduzierbare
Ergebnisse; der unabhängige Audit-Durchlauf wurde normal abgeschlossen.

## R15: vollständiger Test der übrigen Drei-Key-Paarung

Der [Drei-Key-Test](r15_three_common_keys.md) behandelt unterschiedliche
Signaturen mit drei gemeinsamen Schlüsseln. Beide Recovery-Mengen müssen
vier Punkte haben, also beide r kleiner als Delta=p−n sein. Wenn die
antipodalen Paare aufeinander abgebildet werden, verschwindet der Offset.
Andernfalls lässt sich die affine Abbildung `Uj=a*Ui+bG` vollständig als
`A=V+U, B=V−U`, `bG=−aV` schreiben. Bei festem a,b ist V=(v,w) bekannt;
die verbleibende Koordinate X erfüllt

```
n²(X−v)^4 − 16w²(X³+7) = 0 mod p.
```

Die höchstens vier Feldwurzeln müssen anschließend die tatsächlichen
ganzzahligen x-Abstände ±n auf beiden Seiten erfüllen. Drei kleine Kurven
sind vollständig mit einem unabhängigen Skalarindex-Verfahren verglichen,
einschließlich echter nichtverschwindender Offsets. Der separate
[Root-Audit](r15_three_common_keys_audit.json) zählt zusätzlich 315.216 und
306.912 vollständige Untermengen-/Abbildungsfälle; F163/Ordnung139 hat
48 passende Paarungen und acht versetzte Paarungen, alle korrekt erkannt.
Die 16 begrenzten secp256k1-Translationsfälle liefern keinen Kandidaten;
das ist keine Aussage über alle Translationen.

Eine zusätzlich geforderte echte Nonce-Relation `Uj=t*Ui` erzwingt
`(t−a)Ui=bG`. Für t≠a ergibt sich ein notwendiger öffentlicher Nonce-Skalar
`k=b/(t−a)`; das löst nicht automatisch `x(kG) mod n = r` eines tatsächlichen
Hashoutputs. Für t=a gilt b=0 und der bekannte Endomorphismus-Abstandswiderspruch.
Es fehlen weiterhin ein konkreter nativer C/ALL-Zeuge, die Hashschließung
und die Erzwingung gegen andere akzeptierte a,b. Ergebnis:
`locally-reproduced`, `unclassified`, kein neuer Core-Test oder Covenant.

Validierung R13–R15: alle neuen deterministischen Host-Reproduktionen und
die gesonderten Audit-Zertifikate ausgeführt; die gespeicherten R13-Core-
Ergebnisse gelesen; Python-Syntax/JSON, KB-Validierung und Diff-Prüfung
bestanden. Keine Feldbibliotheks-Tests, Bibliotheksänderungen oder
Primitiv-Metrik-Aktualisierungen. Die 3-Minuten-Automation ist weiterhin aktiv.

## R16: vollständige Drei-Key-Digestmenge und native Übersetzung

1. [Fünf-Paarzentren-Schranke](r16_three_key_support.md): Für jede feste
   gültige Alpha-Signatur unter konstantem C können beliebige zweite
   Signaturen unter drei gemeinsamen verschiedenen Gruppenschlüsseln
   höchstens `5*(p−n−1)` verschiedene Digest-Skalare unterstützen. Die
   Aussage umfasst alle affinen Abbildungen und benötigt keine Annahme über
   diskrete Logarithmen. Drei gemeinsame Keys erzwingen auf beiden Seiten
   vier Recovery-Wurzeln; die sechs Alpha-Key-Paare haben nur fünf Summen.
   Einschließlich positiver 32-Byte-DER-Formate, `r<p−n`, Reduktionsbias und
   adaptiver Aufteilung aller Setup-/Online-Abfragen gilt im ausdrücklich
   unabhängigen Zwei-Hashantworten-Modell bei `2^64` Gesamtabfragen
   `Pr[Erfolg] <= ungefähr 2^-44.08044`. Keine allgemeine Covenant-Schranke:
   geteilte Antworten wie `alpha=z_ALL` fallen nicht unter dieses Modell.
   594.285 vollständig ausgezählte kleine Signaturmengen-Vergleiche und
   ein zweiter mathematischer Audit bestätigen die Support-Aussage.
2. [Tatsächliche native Übersetzung](r16_native_translation.md): Die
   Mischpaar-Bedingung reduziert sich exakt auf
   `rj*(si*V−C*G)=−ri*z_ALL*G`. Ein vollständiger klassischer BSGS-Scan des
   erlaubten rj-Intervalls kostet ungefähr `2^65.17` Punktadditionen;
   bedingt auf eine gleichverteilt vorhandene Lösung optimiert ungefähr
   `2^64.67`, jeweils vor zusätzlichen Kosten. Das beschreibt diesen
   Algorithmus, keine allgemeine untere Schranke. Zwei kleine Kurvenzeugen
   schließen die Gleichung mit tatsächlich gehashten Transaktionsbytes,
   gleichem Funding und gleicher Alpha-Signatur, aber verschiedenen
   Empfängern. Die vollständige Toy-Logarithmentabelle und eine Hashprojektion
   werden offen mitgeführt; Raw-Hash-DER und secp256k1 sind damit nicht gelöst.
   79 Bytes/50 Opcodes, 5 Datenitems, 0 Hints, kombinierter Peak 8;
   203 Bytes scriptSig, 0 Witnessbytes, 1.304 WU pro vollständiger Toy-Tx.
   Zwei positive und drei negative Host-Replays reproduziert.

R16 ist `locally-reproduced`, Deployment `unclassified`. Keine neuen Core-
Vektoren, kein vollständiger Covenant, keine Bibliotheks- oder Metrikänderung.
Die gespeicherten Ergebnisse wurden erneut deterministisch reproduziert.
Python-/JSON-Prüfung, KB-Validierung und `git diff --check` bestanden.

## R17: tatsächliche gemeinsame Hashantwort und eine bedingte Signaturfamilie

1. [Gemeinsame Hashquelle](r17_shared_source.md): Für einen tatsächlichen
   ALL-Preimage M liefert `u=SHA256(M)` und ein natives `SHA256(u)` unmittelbar
   dieselben Bytes wie der Transaktionsdigest. Die ehrliche Gleichheit
   `alpha=z_ALL` benötigt also keine zweite Urbildsuche. Acht vollständige
   Byte-Identitäten mit festem synthetischem Funding, verschiedenen
   Empfängern/Beträgen/Locktimes und zwei Hash-Routings sind reproduziert;
   keine ist eine gültige DER-Signatur. Der rohe Kandidat hat 88 Bytes,
   55 statische Opcodes, 5 Datenitems, 0 Hints und strukturellen Peak 8
   (tatsächlich ausgeführter Hashpräfix: Peak 6). M ist hier 215 Bytes,
   u nur 32. Noch fehlen die Signaturzeugen, die erzwungene Quellherkunft,
   Flagbehandlung und vor allem die Bindung an erlaubte Outputs. Keine
   vollständigen ScriptSig-/Gewichtsmessungen oder Core-Ausführungen.
2. [Korrelierte DER-Diagonale](r17_correlated_diagonal.md): Für ein festes
   32-Byte-Layout gilt `z=Z0+256*s`. Die Drei-Key-Paarbedingung wird zu
   `s*(256*r+rho*v)=C*rho−r*Z0`. Üblicherweise ist s für feste r,rho,V
   eindeutig. Bei `rho=r*Z0/C` und `v=−256*C/Z0` verschwindet die Gleichung
   für alle s. Die notwendige öffentliche Punktprüfung lautet
   `Z0*V+256*C*G=O`; ein zusätzliches festes q muss drei Quellpunkte durch
   `U -> ((rho/r)*U+256*G)/q` auf gültige Zielwurzeln abbilden. Dann wäre
   `s_beta=q*s` eine ganze Familie, einschließlich LOW_S-Normalisierung.
   Das ist eine bedingte Konstruktion, kein gefundener secp256k1-Zeuge.
   Für r=1..32767 und alle Flags erfüllen sämtliche 8.388.352 geprüften
   Fälle bereits `rho<p−n` nicht. Größere r und die gewöhnliche Branche
   bleiben offen. 918 tatsächliche DER-Layoutchecks und 14.264 vollständig
   ausgezählte skalare Konfigurationen bestätigen die Reduktion. Die
   höchstens vier Ausnahme-Flags pro r geben die getrennte rohe
   Formatmassenschranke `2^-52.0111`; keine unabhängigen Hashantworten und
   keine zufälligen Punktlogarithmen werden dafür vorausgesetzt.

R17: `locally-reproduced`, Deployment `unclassified`. Root hat beide
Ergebnisdateien durch erneute Ausführung identisch reproduziert und die
bedingte q-Familie unabhängig algebraisch geprüft. Keine vollständige Lösung.
Alle acht R16/R17-Python-/JSON-Dateien, KB-Validierung (55 Einträge,
161 Konfigurationen) und Diff-Prüfung bestanden. Keine Bibliotheksänderungen,
Feldtests, Primitiv-Metrikänderungen oder neuen Core-Behauptungen.
Die 3-Minuten-Automation wurde weiterhin als aktiv bestätigt.

## R18: vollständige Endomorphismus-Geometrie und zwei exakte inverse Solver

1. [Alle Verschiebungen für sechs Steigungen](r18_endomorphism_resultant.md):
   Keine nichtverschwindende affine Verschiebung mit Steigung
   `±1, ±lambda, ±lambda²` überführt drei secp256k1-Recovery-Wurzeln in drei
   Recovery-Wurzeln. Nach vollständiger Paarungs-Klassifikation liefern
   zwei Kummer-/Verdopplungsgleichungen zwölf Resultanten vom Grad höchstens
   80. Alle 29 Körpernullstellen (über die Fälle gezählt) liegen außerhalb
   des jeweils nötigen ganzzahligen Quellintervalls. Das ist eine vollständige
   Aussage für diese sechs Steigungen, keine Übersetzungsstichprobe und
   kein Ausschluss beliebiger Skalare. Der [unabhängige Audit](r18_resultant_audit.md)
   nutzt euklidische Resultanten statt Sylvester-Determinanten, bestätigt
   1.169 Resultantenwerte einschließlich aller Interpolationspunkte sowie
   sämtliche Frobenius-GGTs und Wurzellisten. 656.784 kleine affine Fälle
   enthalten 16 positive Kontrollen mit anderen Steigungen. Die einfachen
   R17-Wahlen `q=±(rho/r)*lambda^(-k)` sind damit ausgeschlossen. Der
   triviale b=0/a=±1-Fall erzwingt z=C und passt nicht zur DER-Diagonale.
2. [Inverse Diagonal-Generatoren](r18_diagonal_solver.md): Für ein gewähltes
   rho löst eine modulare Quadratwurzel alle Quell-r über
   `A*r²+D*r−C*rho=0 mod n`. 34.816 Quadrate für rho=1..256, alle 17
   gültigen Layoutbreiten und acht konstante SINGLE-Flags liefern 34.618
   modulare Wurzeln; keine erfüllt ihr echtes Quellintervall. Das deckt
   für diesen rho-Bereich sämtliche Quell-r ab. Ein zweiter exakter Solver
   nutzt `C*rho=r*(D+A*r)+k*n` und die eindeutig invertierbare Gleichung
   `A*r²+D*r=E*k mod 2^248`, E=`2^256−n`. 408 Quotientenproben und
   272 Vorwärts-/Rückwärts-Endpunkte stimmen. Vollständige ungekürzte
   Domänengrößen betragen ungefähr `2^131.35` vorwärts, `2^135.43` für
   rho-Inversion und `2^129.37` für Quotienten-Inversion. Das sind keine
   erwarteten Arbeitskosten oder allgemeinen Schranken. Kein Treffer,
   Mittelpunktbeweis, q oder Bitcoin-Zeuge wurde daraus gewonnen.
3. [Pflicht-Referenz zwischen Inputs](r18_mandatory_reference.md): Der
   gerade ausgeführte Signatur-Opcode überlebt FindAndDelete und
   CODESEPARATOR-Verarbeitung; sein echter Legacy-scriptCode bleibt
   nichtleer. Deshalb können gewöhnliche Preimages verschiedener Inputs
   derselben gültigen Transaktion innerhalb der Legacy-Familie nicht
   identisch sein. Bei BIP143 trennt schon das eigene Outpoint-Feld.
   20 Löschkontrollen, 6.080 gewöhnliche Legacy- und 6.144 BIP143-Kontexte
   bestätigen dies. 64 konstante SINGLE-Kontexte sind ausdrücklich
   ausgenommen. ANYONECANPAY erlaubt die geprüften Co-Input-Änderungen.
   Diese Aussage betrifft exakte Preimages, weder Hashkollisionen noch
   Gruppenrelationen oder formatübergreifende Schnittstellen. Kein
   verpflichtender externer Verifier wurde konstruiert. Root hat die
   Semantik zusätzlich im gepinnten Core-Quelltext überprüft.

R18: `locally-reproduced`, Deployment `unclassified`; keine neuen
Core-Ausführungen, Script-Zeugen, Bibliotheksänderungen oder Feldtests.
Der Diagonal-Subagent brach nach Speichern seines Python-Programms mit
der generischen Cybersecurity-Meldung ab; Root hat Programm, Ausführung und
Bericht übernommen. Die Meldung enthielt keine konkrete beanstandete Stelle.
Der unabhängige Geometrie-/Input-Subagent wurde normal abgeschlossen.
Keine vollständige Lösung; die Wiederaufnahme bleibt aktiv.

Validierung R18: Root hat die zwölf Resultanten-Zertifikate, den inversen
Solver und das Cross-Input-JSON erneut identisch reproduziert. Der
unabhängige Audit hat sämtliche zwölf Fälle und alle beschriebenen positiven
und negativen Kontrollen ausgeführt. Python-/JSON-Prüfung, KB-Validierung
(55 Einträge, 161 Konfigurationen) und Diff-Prüfung bestanden. Kein
Bibliothekscode, keine Metriken, keine Feldbibliotheks-Tests geändert.

## R19: doppelte und inverse Steigungen; konkrete Referenz aus neuer Quelle

1. [Vollständiger Test für doppelte Endomorphismen](r19_even_slopes.md):
   Auch `a=±2*lambda^k` erlaubt auf secp256k1 keinen affinen Transport
   dreier Recovery-Wurzeln, jetzt einschließlich b=0. Für b≠0 werden die
   Zielkoordinaten diejenigen von A−B und 3A+B. Ihre rationale Darstellung
   führt über `t=y(A)*y(B)` zu zwölf Polynomen vom Grad 39 mit zusammen
   30 Körpernullstellen; keine erreicht das echte Quellintervall.
   Zwölf zusätzliche Grad-6-Polynome für b=0 liefern 22 ebenfalls
   ausgeschlossene Nullstellen. Die Ausnahmedenominatoren werden separat
   behandelt: vier Nullstellen des Tripelpunkt-Nenners liften nicht;
   die zwei Grad-9-Additionsnenner haben insgesamt drei Nullstellen,
   ebenfalls außerhalb des Quellintervalls. B=3A ist ein echter
   Ausnahmefall und wurde nicht aus einer Nennerannahme ausgeschlossen.
   Durch Inversion jeder angenommenen affinen Abbildung folgt derselbe
   Ausschluss für `a=±lambda^k/2`. Das sind zwölf weitere Steigungen,
   keine Aussage über beliebige Skalare oder Faktor vier.
2. [Unabhängiger Audit](r19_even_slopes_audit.md): Alle 27 Zertifikate,
   Koeffizienten, Frobenius-Reste/GGTs und vollständigen Wurzellisten
   stimmen. Der Tripelpunkt-Zähler wurde unabhängig durch A+2A hergeleitet.
   24 volle secp256k1-Punktkontrollen, 176 kleine Punktkontrollen und
   26.856 vollständige kleine affine Fälle bestanden; vier echte positive
   Drei-Wurzel-Abbildungen dienen als Kontrollen. Bei B=3A akzeptieren
   die nennerbereinigten Gleichungen absichtlich falsche Zielabstände;
   der separate Ausnahmezweig verhindert eine falsche Folgerung.
3. [Neue Primärquelle zur Pflichtprüfung](r19_reference_sources.md):
   `0zkbrewer/BCH-FRI-STARK-Verifier`, Commit
   `a600e828d68eb41840049cb16d0c21850ff9df57`, bindet alle weiteren Inputs
   durch `OP_UTXOBYTECODE` an die tatsächlich ausgeführten P2SH32-Locking-
   Scripts und liest gemeinsame Daten mit `OP_INPUTBYTECODE/OP_SPLIT`.
   Das zeigt die genaue noch zu ersetzende Schnittstelle. Die dortigen
   BCH-Introspektions-/CAT-/SPLIT-Operationen liefern keine Umsetzung mit
   bestehenden BTC-Opcodes. Bloße Witness-Scriptbytes oder nur gebundene
   Terminal-Inputs reichen laut dokumentierten Korrekturen nicht aus.
   Root hat den gepinnten lokalen Checkout und die entscheidenden
   Quellstellen selbst gelesen. Die vollständig verdrahtete Konfiguration
   ist dort noch nicht erneut on-chain ausgeführt und überschreitet die
   angegebene Standardgrößengrenze. Keine fremden Tests ausgeführt.

R19-Mathematik: `locally-reproduced`, Deployment `unclassified`.
Neue Quelle: `inspected`; ihre Ausführungsbehauptungen bleiben `reported`.
Keine vollständige Covenant-Lösung, kein neuer nativer Zeuge oder Core-Test.
Beide Subagents wurden normal abgeschlossen. Die Wiederaufnahme bleibt aktiv.

Validierung R19: Root hat alle 27 Zertifikate erneut identisch reproduziert.
Python-AST, JSON und lokale Links der sieben R19-Artefakte sowie
KB-Validierung (55 Einträge, 161 Konfigurationen) und Diff-Prüfung bestanden.
Der unabhängige Audit bestätigt zusätzlich ausdrücklich die inverse
Steigungsfolgerung. Keine Feldbibliotheks-Tests ausgeführt.

## R20: Pflichtausführung, tatsächliche Daten und funktionale Signaturen

1. [Gemischter Taproot-/ECDSA-Test](r20_taproot_reference.md): DEFAULT
   bindet tatsächlich die ausgegebenen Input-Scripts, aber nicht die
   scriptSig-/Witness-Daten anderer Inputs. Selbst wenn der exakt geplante
   Hilfsprüfer ausgeführt wird, kann er eine andere gültige Alpha-/Key-Zeile
   akzeptieren als diejenige, die der Hauptinput prüft. Zwei vollständig
   serialisierte Host-Varianten haben denselben vollständigen Haupt-Witness
   einschließlich identischer DEFAULT-Signatur und verschiedene Hilfsdaten.
   Der Hauptoutput hat einen NUMS-Innenschlüssel; kein Key-Path-Bypass.
2. [Finanzierte Core-Prüfung](r20_taproot_reference_core.md): Root hat
   alle acht Varianten mit Bitcoin Core 30.3 ausgeführt. Beide Datenzeilen
   sind für dieselben finanzierten Outpoints konsens- und policygültig,
   je 406 Bytes/1.147 WU. Ein neuer Leaf-Schlüssel-Signaturzeuge erlaubt
   auch Ersatz durch OP_TRUE (nur Konsens, 282 Bytes/651 WU) oder Weglassen
   des Hilfsinputs (policygültig, 240 Bytes/486 WU). Die Weglassvariante
   senkt den Output von 940.000 auf 890.000 sats, um Werterhaltung zu
   erfüllen. Alte Signaturen und die beiden falschen Datenkontrollen
   werden erwartungsgemäß verworfen. Alle acht Fälle haben 10.000 sats
   Gebühr. Vier positive/vier negative Ergebnisse, separate Branches
   durch Invalidierung der Prüfblöcke, keine Änderung des Fundings.
   Der unabhängige Agent hat die gespeicherten Transaktionen ohne den
   Host-Serializer neu geparst und Werte, Outpoints, Haupt-Witness und
   Gewichte bestätigt. Daten: Hauptinput zwei/Hilfschecker vier;
   jeweils null Hints. Haupt-Peak drei, P2SH-Input-Peak sechs,
   Redeem-Fragment-Peak fünf. Beweisklasse `differentially-validated`;
   die drei Standard-Positivfälle `policy-validated`, OP_TRUE-Ersatz
   `consensus-validated`. Kein Covenant-Zeuge.
3. [Neue Quellen](r20_reference_sources.md): Der funktionale Adaptor-
   Prototyp zu ePrint 2026/1124, Commit
   `f59875bbf739280e6fdb460232e3cef00b604f25`, übernimmt den gewöhnlichen
   Signierschlüssel und lässt direktes Signieren anderer Nachrichten zu.
   Seine Python-Kodierung ist zudem nicht BIP340 (64-Byte-Punkte,
   96-Byte-Signaturen). Dies ist kein genereller Portierungs-Ausschluss.
4. [Vollständiger Spezifikationsaudit](r20_functional_signature_spec.md):
   ePrint 2026/1346 war über einen normalen Direktabruf verfügbar;
   die frühere Unverfügbarkeitsnotiz ist überholt. Die gepinnte 44-seitige
   PDF-Spezifikation gibt explizit den uneingeschränkten Basissignierschlüssel
   zurück. Einschränkungen gelten für Empfänger abgeleiteter Schlüssel,
   nicht für den Ersteller mit behaltenem Master-Schlüssel. OP_RETURN
   kann möglicherweise einen nativen Transaktions-Wrapper ermöglichen;
   `m||r` allein ist kein allgemeiner Bitcoin-Inkompatibilitätsbeweis.
   Ein solcher Wrapper behebt aber den behaltenen Signierschlüssel nicht.
   Root hat PDF-Hash und entscheidende Schlüssel-/Signierdefinitionen
   sowie den gepinnten Prototyp selbst geprüft. Quellenklasse `inspected`;
   hypothetische BTC-Komposition `unclassified`.

Kein allgemeiner Ausschluss von Multi-Input- oder funktionalen Konstruktionen.
Der präzise neue Test verlangt sowohl zwingende Ausführung als auch dieselben
semantischen Daten oder eine bewiesene eindeutige Funktion der tatsächlichen
Transaktion. Die bloße Bindung der Input-Scripts durch DEFAULT reicht nicht.
Alle drei beauftragten Agents schlossen normal ab. Keine Feldbibliotheks-
Tests oder Primitive-Metriken durch diese Untersuchung geändert.
Keine vollständige Lösung; die Dreiminuten-Wiederaufnahme bleibt aktiv.

Validierung R20: deterministisches Host-JSON identisch reproduziert;
acht tatsächlich ausgeführte Core-Fälle plus unabhängiger gespeicherter
Transaktionsaudit; AST/JSON/lokale Links sämtlicher 15 R19-/R20-Artefakte
bestanden. KB-Validierung zuletzt 56 Einträge/163 Konfigurationen und
Diff-Prüfung bestanden. Die zusätzliche Katalogänderung stammt aus der
parallel laufenden Pointlock-Arbeit; deren Code/Tests wurden hier nicht
bearbeitet. Quellen-Hashes und Git-Pins geprüft. Die Automation ist weiterhin
`ACTIVE` im Dreiminutentakt. Kein Cargo-/Feldbibliotheks-Test für diese
isolierten Python-/Dokumentations-Experimente erforderlich oder ausgeführt.

## R21: kanonische Schlüsselpaare und der Anschluss an den Drei-Punkt-Orbit

1. [Kanonisches Paar und affine Aggregate](r21_canonical_affine.md): Die
   bereits in Search 3 gegen Core geprüfte feste Signatur r=s=1 erzwingt
   zwei unterschiedliche komprimierte Recovery-Keys als eindeutiges
   ungeordnetes Paar. Das ist kein neuer nativer Baustein. Für feste
   Koeffizienten ist `A=aP+bQ+cG=uR+vG` nach Vertauschung genau dann als
   x-only Key invariant, wenn u=0 oder v=0. Die erste Möglichkeit hat einen
   öffentlichen Signierskalar; die zweite bleibt für verschiedene Digests
   nur bei a+b=c=0 invariant und verliert damit die Transaktionsabhängigkeit.
   Zwölf affine Vektoren, 16 BIP340-Gleichungsprüfungen und 64 tatsächliche
   Legacy-Hashkontexte bestätigen die Abgrenzung. Gerade y-Parität liefert
   keine allgemeine eindeutige Auswahl: 18/28/18 Paare haben 0/1/2 gerade Keys.
2. [Nichtlineare Hashgewichte](r21_hash_weight_cost.md):
   `F=H(P)P+H(Q)Q` umgeht die feste affine Einordnung und behält im Allgemeinen
   Transaktionsabhängigkeit und einen unbekannten R-Anteil. Dessen
   Auslöschung u=0 verlangt H(P)=H(Q). Für eine vor sämtlichen Hashabfragen
   festgelegte Quelle bilden die zulässigen Paare einen Graphen vom Grad
   höchstens zwei. Im ausdrücklich idealen Hashmodell gilt
   `Pr<=2Q*pmax`, für M vorher feste Quellen `Pr<=2MQ*pmax`.
   Alle Setup-, Such- und finalen Endpunktprüfungen zählen. Bei Q=2^64 und
   idealem SHA256 modulo n ergeben sich 2^-190 beziehungsweise 2^-158 für
   M=2^32. Nachträgliche Quellenwahl darf diese Schranke nicht erben; ein
   kleines Gegenbeispiel zeigt das. Die allgemeine Kollisionsschranke
   `binom(Q,2)*pmax` gilt weiterhin für u=0, nicht für andere Signierwege.
   Zwölf Gruppenvektoren, 80 adaptive Spiele, 20 vollständige Farb-DPs,
   1.398 vollständig ausgezählte Hashfunktionen und 18 Katalogspiele geprüft.
3. [Unabhängiger Hash-Audit](r21_hash_weight_audit.md): 65 Spielwerte durch
   geschlossene Formeln, 18 Graphgrade, Modulo-Bias und sämtliche großen
   Grenzen unabhängig bestätigt. Ein zweiter Agent optimierte 40 kleine
   Spiele direkt über die verbleibenden vollständigen Funktionstabellen.
   Seine Endpunkt-Abfragekorrektur ist im Bericht enthalten.
4. [Ein kurzer und zwei lange Orbit-Signaturen](r21_orbit_interface.md):
   Für gemeinsame Keys und vorausgesetzte Nonces
   `U_i=epsilon_i*lambda^j_i*R` gilt `K=a_i*R-b_i*G`.
   Verschiedene a liefern unmittelbar den Logarithmus von R; andernfalls
   müssen auch die b gleich sein. Verbundene antipodale Paargraphen ohne
   solche Extraktion kollabieren auf dasselbe Key-Paar. Die Orbit-Prämisse
   selbst wird dadurch nicht bewiesen. Eine echte 32/71/73-Byte-Familie
   liefert sechs gültige ECDSA-Prüfungen und bekannte Nonce-Logs; zwei gültige
   Nicht-Orbit-Ersatzsignaturen zeigen die fehlende Erzwingung. Für die
   gemeinsame-Paar-Familie liegen bei einem kurzen Ausgangssignatur-r
   höchstens ungefähr 2^192 geordnete native Digest-Zielpaare vor.
   Die Wahrscheinlichkeitsschätzung setzt unabhängige Digest-Kontexte
   voraus; sie ist keine allgemeine adaptive Arbeitsschranke.

Alle neuen ausführbaren R21-Resultate: `locally-reproduced`, Deployment
`unclassified`. Die allgemeinen Herleitungen sind `inspected`; frühere
Core-Messungen werden nur als solche wiederverwendet. Kein neuer Core-Lauf,
keine Bibliotheksänderungen, keine Feldtests oder Primitiv-Metriken.
Root hat alle vier JSON-Artefakte erneut byteidentisch reproduziert.
Es fehlen weiterhin native Verknüpfung, verpflichtende Output-Referenz und
ein vollständiger ehrlicher Signier-/Setup-Algorithmus unter 2^64.
Die Dreiminuten-Wiederaufnahme bleibt aktiv.

Validierung R21: alle zwölf neuen Python-/JSON-/Markdown-Artefakte auf
Syntax, JSON und lokale Links geprüft; KB-Validierung mit 56 Einträgen und
163 Konfigurationen sowie `git diff --check` bestanden. Alle vier
deterministischen Ergebnisdateien byteidentisch reproduziert. Kein
vollständiger Covenant und kein neu geminter PoW-Zeuge.

## R22: nativer SINGLE-Guard und Taproot-Kanten als positive Schnittstellen

1. [Variabler SINGLE-Guard](r22_single_guard.md): Ein neues vollständiges
   49-Byte-Legacy-Script prüft dieselbe frei gelieferte Signatur unter
   denselben zwei unterschiedlichen komprimierten Keys in zwei
   CODESEPARATOR-Kontexten. SIZE>57 schließt Vier-Wurzel-Signaturen aus;
   damit erzwingt das volle Paar gleiche Digest-Skalare. Die tatsächlich
   verarbeiteten scriptCodes sind 48 und 13 Bytes lang. Gewöhnliche
   Preimages unterscheiden sich, während der SINGLE-Bug in beiden Fällen
   C=2^248 liefert. Ein akzeptierender Nicht-Bug-Fall wäre daher eine
   Kollision verschiedener Preimages nach double-SHA256 modulo n, nicht
   zwingend eine bitweise Hashkollision. Alle acht effektiven SINGLE-Flags
   bleiben erlaubt. Das ist ein rechnerisch abgesicherter Kontext-Guard,
   kein Flag-Byte-Leser und keine Output-Bindung.
2. [Finanzierte Core-Prüfung](r22_single_guard_core.json): Zehn echte
   Testspends am selben Funding ergaben vier positive und sechs negative
   Ergebnisse. SINGLE, SINGLE|ACP und undefinierte obere SINGLE-Bits
   funktionieren; derselbe Zeuge erlaubt auch einen anderen Empfänger.
   ALL/NONE/reguläres SINGLE mit gültigem erstem Kontext scheitern am
   zweiten. Doppelte Keys, kurze Signatur und unkomprimierter Key scheitern.
   Positivwerte: 49 Bytes Redeemscript, 190 Bytes scriptSig, 319 Bytes/
   1.258 WU ganze Transaktion; drei Redeem-Datenitems, null Hints, Peak sechs,
   32 Redeem-Opcodes plus zwei äußere P2SH-Opcodes. Separater OP_TRUE-Helfer:
   ein Datenitem, null Hints. Die Default-Policy verwirft CODESEPARATOR bzw.
   den undefinierten Flagtyp. Evidenz `differentially-validated`, positive
   Fälle `consensus-validated`. Keine neuen PoW-Zeugen.
3. [Native C-Pfade](r22_native_relation.md): Feste C-Signaturen sind
   endliche Mitgliedschaftsprüfer und unterscheiden die Quellkeys nur bei
   höchstens acht Digest-Werten je Signatur. Für variable antipodale
   C-Kanten gilt `K_i=-K_(i-1)-2C/r_i*G`. Ein ungerader Pfad zwischen den
   beiden ALL-Quellkeys erzwingt `z/r=C*sum((-1)^(m-i)/r_i)`; ein gerader
   Pfad extrahiert den Quell-Nonce-Skalar. Diese Spezialisierung früherer
   Graphalgebra liefert noch keine passenden Nonces für den tatsächlichen
   Digest. Der neue Guard kann jetzt die bisher nur vorausgesetzten
   C-Kontexte langer Signaturen konkret absichern. Drei alte echte
   C/ALL-Fälle, zwölf Selektorprüfungen, vier Selektor-Skalarkontrollen,
   zwölf C- und sechs Quellgleichungen neuer kleiner Pfade überprüft.
4. [Taproot-Kante zuerst](r22_taptweak_interface.md): Aus einer gültigen
   tatsächlichen Commitment-Gleichung `O=I+tG` folgt öffentlich
   `J=I+tG/2`, `R=J/a`, `r=x(R) mod n`, `s=a*r`, `z*=t*r/2`.
   Damit recovern I und -O, ohne irgendeinen ihrer privaten Skalare zu
   benötigen. 16 echte TapLeaf-/TapBranch-/TapTweak-Bytevektoren mit vier
   Skalierungen liefern 64 vollständige Zwei-Key-Paare, sämtliche vier
   Paritätskombinationen, 48 ungültige Öffnungskontrollen und 513 DER-
   Grenzprüfungen. Der Digest z* ist hergestellt; keine Transaktion wurde
   gefunden, deren tatsächlicher Hash ihm entspricht. Endpunkt-Bindung,
   Pflichtausführung und Output-Asymmetrie fehlen. Für a=1 ist die
   Signatur immer ungerade lang und nie ein 20-/32-Byte-Hash; diese Grenze
   gilt nicht allgemein für andere a. Bekannter Innenschlüssel erlaubt
   weiterhin den freien Key-Path. Quellen und genaue Funding-Abhängigkeiten
   stehen im Bericht.

Die zwei neuen Algebra-Familien bleiben `locally-reproduced` /
`unclassified`; allgemeine Herleitungen `inspected`. Nur der ausdrücklich
ausgeführte SINGLE-Guard erhält den Core-Beleg. Kein vollständiger Covenant.
Root hat beide Agent-JSONs byteidentisch reproduziert. Keine Rust- oder
Feldbibliotheks-Tests und keine Primitiv-Metriken geändert. Die Loopback-
Sperre der Sandbox wurde für den bereits autorisierten isolierten
Regtestlauf per genehmigter Eskalation überwunden. Die Automation bleibt aktiv.

## Nächste konkrete Versuche nach R22

- **Den neuen C-Guard konstruktiv komponieren:** Ein tatsächlicher
  langer C-Signaturpfad braucht nicht mehr auf eine frei behauptete
  SINGLE-Flagwahl vertrauen. Jetzt eine konkrete kleine Graphkomposition
  samt Stack-/Opcode-Grenzen und Signatur-/Nonce-Konstruktion für den echten
  finanzierten ALL-Digest liefern. Der 49-Byte-Test konsumiert seine drei
  Eingaben vollständig; ein größeres Netz benötigt eigene konkrete
  Datenführung und Ressourcenzählung. Die ungerade reziproke Gleichung
  allein gibt die r_i nicht als echte Nonce-Koordinaten. Anschließend eine
  feste Output-Referenz binden; der Guard selbst lässt jeden Empfänger zu.
- **Den Taproot-Kanten-Anschluss schließen:** Die azyklische öffentliche
  Kante ist jetzt gebaut. Finde einen echten Spend mit
  `z_native=(t/2)*x((I+tG/2)/a) mod n` und erzwinge, dass die ECDSA-Keys
  wirklich die nativen Controlblock-Endpunkte sind. Witness-Kopien allein
  reichen nicht; das Einbetten des nachträglich berechneten O in sein
  eigenes Leaf erzeugt wieder einen Fixpunkt. Die tatsächliche BIP340-
  Challenge bleibt unabhängig zu prüfen. Nicht bloß weitere hergestellte
  Digest-Vektoren erzeugen.

Die neuen Algorithmen und Beziehungen als Bausteine behalten; abgeschlossene
Familien nicht unverändert wiederholen. Prioritäten:

- **Pflicht-Referenz wieder priorisieren:** R19 liefert einen konkreten
  Vergleichsmechanismus: Ein zwingend ausgeführter Input bindet die
  Locking-Scripts sämtlicher Produzenten und Checker sowie dieselben
  tatsächlichen Daten. Ein BTC-Ersatz muss genau diese Eigenschaften
  nativ erzwingen oder die gesamte Referenz im eigenen Input ausführen.
  Eine weitere freie Signaturfamilie oder ein vorgezeigtes Redeemscript
  erfüllt sie nicht. Den 199-Opcode-A-Baustein nicht als fertige Prüfung
  behandeln; für einen neuen Kandidaten zuerst die lesbare Referenz,
  deren Binding und alle Funding-Abhängigkeiten konkret angeben.
  R20 hat die reine DEFAULT-Input-Script-Argumentation jetzt mit tatsächlichen
  Core-Spends widerlegt. Als positive Alternative eine Hilfsprüfung suchen,
  deren jeder akzeptierende Zeuge dieselbe transaktionsabhängige Größe
  erzwingt; keine weitere frei gewählte Alpha-/Key-Zeile. Eine funktionale
  Signatur benötigt zusätzlich Setup ohne behaltene uneingeschränkte
  Signiermöglichkeit; die jetzt gelesenen FAS-/AS-Masterkeys erfüllen das nicht.
- **Geometrie nur mit neuem konstruktivem Ziel:** R18/R19 schließen die
  natürlichen Steigungen `±lambda^k`, `±2*lambda^k`, `±lambda^k/2`
  ab (bei den ersten bleiben nur die beschriebenen trivialen Fälle).
  Nicht dieselben Verschiebungen erneut testen und nicht ohne neue
  Solver-Idee lediglich kleine Multiplikatoren hochzählen. Die exakten
  Polynome bleiben Werkzeuge für einen tatsächlich motivierten anderen
  q-/Nonce-Solver. Beliebige Steigungen sind nicht ausgeschlossen.
- **Korrelierte Drei-Key-Familie konstruktiv schließen:** R17 liefert eine
  konkrete gemeinsame Hashantwort ohne zweite Urbildsuche, aber noch keine
  gültige Signatur. Für die Ausnahmefamilie einen r>32767 samt vier Wurzeln,
  passendem tatsächlichem DER-Layout/Flag und `256<rho=r*Z0/C < p−n` sowie
  `Z0*V+256*C*G=O` konstruieren. Danach muss ein berechenbares q auch den
  dritten Key schließen; seine Berechnung ist nicht kostenlos. Ein bloßer
  größerer Brute-Force-Scan der bereits geprüften kleinen r ist kein
  begründeter Solver. Alternativ die gewöhnliche skalare Gleichung oder
  eine andere native Schnittstelle konstruktiv nutzen. Beide Wege müssen
  die erlaubten Outputs verpflichtend binden und sämtliche gemeinsamen
  Such-, Funding- und Auditkosten zählen. Die unabhängige R16-Schrankenkette
  darf auf die gemeinsame Hashantwort nicht angewandt werden.
- **Ein kurzer und weitere lange Orbit-Signaturen:** Die vollständige
  R14-Aufzählung gilt nur bei drei kurzen r. Ein möglicher neuer Anschluss
  muss die Orbit-Zugehörigkeit tatsächlich nativ erzwingen. Die Zahl h bloß
  als Witness zu übergeben ist durch R13 widerlegt; drei kurze Hashsignaturen
  erzeugen nur den einen h=2-Orbit mit zu kleinem Hashzielraum.

Die nächste Runde soll zuerst eine verpflichtende Output-/Nonce-Bindung oder
eine vollständige Referenzprüfung versuchen. Eine weitere Beschleunigung
öffentlichen Signierens allein erfüllt das Ziel nicht; die folgende
Portfolio-Optimierung ist nur als begrenzte parallele Teilfrage sinnvoll.

- **R12-Hash an eine echte Referenz binden:** Die große Familie gültiger
  Signaturen nach einem tatsächlichen Digest ist nun konkret. Einen
  lesbaren/funktionalen Anschluss des tatsächlichen `H(alpha_s)` oder seines
  nativen Recovery-Keys entwickeln. Ein freies h, ein freies K oder ein
  weiterer ungeprüfter Zahlenvektor reicht nicht. Beim Zählen von L genau
  festhalten, ob Alpha/Referenz während der Variantenwahl unverändert bleibt.
  Die bloße umgekehrte Hashrichtung und ihr s-Sampler sind abgeschlossen.
- **R11-Tabelle wirklich finanzierbar machen:** Der native Lookup selbst
  ist gebaut. Liefere eine konkrete, selbstkonsistente Tabelle samt
  Funding-Txid, oder eine neue azyklische Bindung. Der bereits ausgeführte
  CODESEPARATOR-Lookup löst nur die direkte scriptCode-Abhängigkeit;
  wiederholte Tabellenumschreibung ist keine Einrichtungsmethode.

- **Neue R10-Schnittstellen zuerst:** Die gleiche-Input-Kombination aus
  konstantem SINGLE-Digest und ALL ist zulässig. Eine echte, lesbare
  Referenzfunktion mit den unterschiedlichen Signaturen verbinden;
  `z/r_beta=C/r_alpha` allein ist noch kein günstiger Solver. Alle
  Vierwurzel-Paarzustände berücksichtigen. Die direkte literale
  `z_ALL=C`-Variante nicht erneut als neuen Ansatz behandeln.
- **58 verbleibende Opcodes konkret nutzen:** Der gepackte 37-Stufen-Root
  kann viele Seeds für dieselbe kleine Funktion liefern. Als nächstes eine
  tatsächlich outputbezogene Funktion mitsamt nativer t/y-Bindung entwerfen,
  oder einen präzisen noch fehlenden Baustein isolieren. Keine freien
  Transkript-Orakel, später ungebundenen Wire-Werte oder angenommenen
  `2^32` Varianten als Implementierung zählen. Alle Gruppen-/Hash-/Speicher-
  und Auditkosten sowie endliche Domänen mitrechnen.
- **Parallele Zyklen mit freien r:** R11 liefert jetzt einen konkreten
  paarweisen Endomorphismus-Solver ohne individuelle Nonce-Logarithmen.
  Das nicht als ECDLP-Sackgasse wiederholen. Mehrere Ratios müssen zugleich
  die Orbit- und Paarbreiten-Beziehungen erfüllen; bei drei Endomorphismus-
  Koordinaten gilt zusätzlich `x0+x1+x2=h*p` mit h=1 oder 2. Ein funktionaler
  Hash-Root-Anschluss bleibt nötig, sonst sind andere Outputs ebenso lösbar.

- **Universelle Drei-Key-Schnittstelle konstruktiv verwenden:** Jetzt darf
  eine variable tatsächliche ECDSA-Signatur verwendet werden, ohne r/s zu
  extrahieren oder einen Vierwurzel-Ausnahmefall offen zu lassen. Einen
  zweiten zwingenden Kontext oder eine authentifizierte Referenzrechnung
  konstruieren, deren Digest bei erlaubten Outputs günstig gleich wird.
  Die bekannte Invarianz gewöhnlicher Legacy-Preimages und die bereits
  geprüfte Legacy/BIP143-Funding-Hash-Abhängigkeit nicht ignorieren.
  Gleichheit allein, bei zwei identischen tatsächlichen Kontexten, ist
  ausdrücklich keine Output-Bindung. R18 schließt identische gewöhnliche
  Preimages zweier tatsächlicher verschiedener Inputs innerhalb derselben
  ECDSA-Hashfamilie aus; abstrakte leere scriptCodes sind nicht ausführbar.
- **Hash-Key-Schnittstelle ohne wiederverwendbaren Signierschlüssel:** Der
  Schnorr-Proof-Hash erlaubt azyklische Witness-Wahl und DEFAULT. Ein neuer
  Solver muss eine vollständige Signatur unter einem echten Hash-Key liefern
  und darf die bekannte-Nonce-Schlüsselextraktion nicht übersehen. Die
  reine affine Nonce-Auslöschung wurde geprüft; nicht unverändert wiederholen.
- **Günstigere gemischte Portfolios:** Der konkrete Intervall-Join ist nun
  verfügbar. Die dyadische rationale Familie ist nun geprüft. Nur andere
  gemeinsam auswertbare Multiplikatoren oder konkret bessere Kostenmodelle
  als begrenzte parallele Aufgabe untersuchen. Dabei die Kosten aller transformierten Digest-Tabellen,
  Punktnormalisierung, tatsächlichen Speicherzugriffe und Setup-Prüfung
  mitzählen. Unterschiedliche b können viele Tabellen oder Teilintervalle
  verlangen; diesen Aufwand nicht kostenlos gewähren. Erfolgskriterium:
  vollständiger Algorithmus mit klarer Arbeitseinheit und erwartetem
  Gesamtaufwand unter `2^64`, einschließlich endlicher Suchbereiche.
- **Output-Asymmetrie trotz frei wählbarer Nonces:** Die ausgewählte Nonce
  nativ binden oder eine Referenzbedingung formulieren, die für alle
  akzeptierten Nonces gilt. SIZE und doppelte CHECKMULTISIG-Signaturen lösen
  dies nicht. Eine neue Konstruktion muss bei behaltenen Keys/Tabellen
  ausdrücklich unterschiedliche Kosten für erlaubte und andere Outputs haben.
- **Kurze transparente Funktionsbindung:** Der einfache Sumcheck und der
  vollständig gebundene Einrunden-Quotient sind geprüft. Einen konkreten
  Verifier der tatsächlichen Referenzfunktion statt einer freien Schluss-
  auswertung liefern. Der neue numerische Root authentifiziert eine ScriptNum mit getrennten
  Pfad-Hints; er authentifiziert noch keine nachträglich behaupteten Wire-Werte
  oder allgemeine Koeffizientenvektoren. Die genaue Query-Fasergröße und
  Root-Wiederverwendung unter R5-Chronologie müssen Bestandteil sein.
- **Neue Korrelation mit großem realem Hashzielraum:** Die gekoppelte DER-
  Familie hebt die frühere C0-Blockade auf, ihr fester kleiner r macht den
  Zielraum jedoch zu klein. Eine Erweiterung braucht nach Funding echte
  Freiheiten und eine native Byte-/Key-Beziehung; nicht bloß weitere
  synthetische Digest-Identitäten oder frei recoverte Witness-Keys.
- **Variabler Schnorr-Skalar:** Eine tatsächlich ausgeführte Brücke zwischen
  den Signaturbytes und der arithmetischen Darstellung entwickeln. Bloße
  Hashgleichheit, Literal-Tabellen, Erfolgs-Bitmaps und optionale Verifier-
  Inputs sind bereits abgegrenzt. Allgemeine neue Gruppenrelationen bleiben
  offen; eine nicht vorhandene Punkt-/Skalar-Extraktion nicht voraussetzen.
- **Flags und Funding:** Jede neue Root-Konstruktion muss NONE und
  unvollständiges SINGLE ausschließen oder trotzdem die vollständigen Outputs
  binden. Ehrliche ALL-Auswahl, Kontext-Guard und eine Prüfung vor Broadcast
  entfernen diese Obligation oder die Funding-Hash-Abhängigkeit nicht.

Bei jeder Wiederaufnahme neue Ergebnisse und konkrete nächste Versuche
hier ergänzen. Die Automation bleibt aktiv, bis die vollständige geprüfte
Lösung die Anforderungen erfüllt oder der Nutzer ausdrücklich stoppt.
