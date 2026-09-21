# Geheimnisfreier Exact-Output-Covenant: weitere Untersuchung

Stand: 17. September 2026. **Keine vollständige Lösung unter `2^64` ehrlicher
Gesamtarbeit gefunden.** Die Untersuchung liefert einen konsensgeprüften
DER-Prüfbaustein, ein ausgeführtes Gegenbeispiel und eng begrenzte
Suchkostenschranken. Keines davon ist ein fertiger Covenant oder ein allgemeiner
Unmöglichkeitsbeweis.

Die [zweite Untersuchung](second_pass.md) ergänzt zwölf weitere Core-Fälle,
einen nativen Zyklus aus 16 Signaturprüfungen und eine exakte Analyse der
Kapazität von Signaturlängen. Auch diese Kandidaten liefern keine vollständige
Output-Bindung; die konkreten Grenzen sind dort reproduzierbar festgehalten.

Die [Runde mit sieben Subagents](seven/README.md) verbessert den nativen
Zwei-Treffer-Baustein auf 199 Opcodes bei etwa 56 Bit effektivem Nonce-Raum
und ergänzt 18 Core-Fälle. Sie korrigiert die Reichweite der nachstehenden
Pfadschranke: Ein fester erster Nonce plus ein langer zweiter Pfad wird davon
nicht ausgeschlossen. Die vollständige Output-Darstellungsbrücke fehlt weiter.

Der [fortlaufende Stand bis R12](continuation/STATE.md) enthält inzwischen
eine nahezu vierfach günstigere exakte Binohash-Längensuche sowie einen neuen
Intervall-/Kongruenz-Join für öffentliche Nonce-Portfolios. Vier mit dem Join
gefundene echte Signaturen bestehen Core-Konsens und Policy. Der Join beseitigt
die naive quadratische Paarprüfung; vollständige Kosten unter `2^64` und die
verpflichtende Output-Referenz sind weiterhin offen.

R9 ergänzt einen exakt geprüften Satz für **jede** gültige ECDSA-Signatur:
Drei verschiedene gemeinsame Public Keys erzwingen Gleichheit zweier
Digest-Skalare, auch bei den r+n-Ausnahmen. Vollständige Polynom-Wurzelzählung
und eine unabhängige Matrixrechnung stimmen überein. Die variable
Signaturschnittstelle besteht vier positive und vier negative Core-Tests;
auch sie liefert noch keinen verpflichtenden Soll-Output-Kontext.

R10 prüft SINGLE und ALL im selben gesperrten Input, zwei parallele native
Key-Zyklen und einen gepackten numerischen Root. Der letzte Entwurf bindet
eine kleine affine Funktion mit 143 Opcodes und lässt 58 weitere übrig.
Alle drei Ansätze sind reproduzierte Teilbausteine; die vollständige native
Soll-Output-Prüfung und ihr Gesamtaufwand bleiben offen.

R11 konstruiert freie SINGLE/ALL-Signaturpaare nach dem tatsächlichen
Transaktions-Digest durch ein zweidimensionales Endomorphismus-Gitter.
Drei unterschiedliche Output-Varianten desselben finanzierten Inputs
bestehen Core-Konsens und Policy, drei fehlerhafte Varianten scheitern.
Das ist ein neuer nativer Solver; gerade seine freie Verwendbarkeit für
andere Outputs zeigt, dass die Hash-/Soll-Output-Bindung noch ergänzt werden muss.

R12 bindet den Hash einer tatsächlichen vollen Signatur an denselben nativen
Baustein. Eine große öffentliche Skalarfamilie erlaubt Hashversuche ohne
Kurvenarbeit pro Versuch; 48 Host-Zeugen und 24 negative Fälle bestehen.
Der Hash bleibt eine frei gelieferte Referenz ohne Soll-Output-Auswertung.

## Frage und Sicherheitsmodell

Gesucht ist eine Selbstbindung an die vor Einzahlung festgelegten Beträge,
Reihenfolge und scriptPubKeys sämtlicher Outputs. Der Einzahler darf einen
vollständigen vorgesehenen Spend vor Veröffentlichung der konkreten Funding-
Transaktion prüfen. Andere Metadaten dürfen variieren. Der Ersteller darf
sämtliche Schlüssel, Preimages, Tabellen und Suchergebnisse behalten und
unerlaubte Alternativen schon vor der Einzahlung vorbereiten.

Gezählt wird ehrliche Gesamtarbeit einschließlich Setup und dessen Prüfung,
nicht parallele Laufzeit. Es sind nur vorhandene Bitcoin-Opcodes erlaubt;
Schlüsselvernichtung ist ausgeschlossen. Konsens und Standard-Relay werden
getrennt geprüft. Ausgangspunkt war die Nutzerübergabe vom 17. September 2026,
einschließlich des uninstanziierten Zwei-Treffer-Modells und der korrigierten
64/20/64-Byte-ColliderScript-Brücke.

## 1. DER prüfen ohne Recovery-Schlüssel

Dieses vier Byte lange Legacy-Redeemscript prüft einen Hash-to-DER-Treffer:

```text
OP_SHA256 OP_0 OP_CHECKSIG OP_NOT
hex: a800ac91
```

`OP_CHECKSIG` verwirft fehlerhafte nichtleere DER-Kodierungen sofort. Eine
wohlgeformte Kodierung erreicht dagegen die Prüfung mit dem leeren Public Key,
die false liefert. `OP_NOT` macht daraus true. Der leere Schlüssel wird
absichtlich benutzt; es findet keine erfolgreiche ECDSA-Verifikation statt.

Der bereits bekannte Preimage-Treffer
`00000000000000000200a8013bbb8678` wird damit von Bitcoin Core akzeptiert.
Ein mutiertes Preimage wird abgewiesen. Es wurde **kein neuer Treffer gemined**.
Das Gate ist Legacy-konsensgültig, aber wegen der Public-Key-Kodierung nicht
standardmäßig relayfähig. Im generischen Witness-Parser muss zusätzlich
`OP_SIZE <32> OP_EQUALVERIFY` den leeren Signatur-Bypass schließen; nach
`OP_SHA256` ist die Länge bereits garantiert.

Für uniforme 32-Byte-Hashwerte lautet die exakt gezählte syntaktische
Trefferwahrscheinlichkeit

```text
p = 780555 / 2^65 = 2^-45.4258592336.
```

Dies ist eine Modellrechnung, keine gemessene Mining-Leistung. Der r-Wert muss
hier nicht zu einem Kurvenpunkt passen. Der zusätzliche Recovery-Schlüssel Q
des bisherigen Polyglot-Gates entfällt. Eine davor gesetzte feste ALL-Signatur
kann weiterhin den ursprünglichen Schlüssel P an die Transaktion binden:

```text
<300602010102010101> OP_OVER OP_CHECKSIGVERIFY
OP_SHA256 OP_0 OP_CHECKSIG OP_NOT
```

Dieser vollständige P-gebundene Vorschlag wurde **nicht gemined oder mit einem
erfolgreichen vollständigen Spend getestet**. Das Berechnen von P für neue
Transaktionskandidaten benötigt weiterhin Kurvenarbeit. Der isolierte
DER-Parser selbst liest keinen Transaktionshash. Ein unerlaubter Spend kann
dasselbe öffentliche Suchverfahren benutzen; damit fehlt die gesuchte
Arbeitsasymmetrie. [Herleitung und Grenzen](two_hit_native_predicates.md).

## 2. Gegenbeispiel zu einer Signatur-Abkürzung

Dieselbe frei gewählte ECDSA-Signatur unter demselben frei gewählten Schlüssel
kann zwei **verschiedene** ALL-Digests bestätigen. Für `r=x(G)` gilt:

```text
s = (z1-z2)/2 mod n
d = -(z1+z2)/(2r) mod n
P = dG.
```

Die beiden Prüfungen erhalten die Noncepunkte `G` und `-G`, deren
x-Koordinaten gleich sind. Der vier Byte lange Gegenbeispiel-Verifier lautet
`OP_2DUP OP_CHECKSIGVERIFY OP_CODESEPARATOR OP_CHECKSIG`.

Die Gleichungen wurden gegen OpenSSL geprüft. Anschließend akzeptierte
Bitcoin Core zwei tatsächlich finanzierte P2SH-Spends desselben Outpoints
mit verschiedenen Empfängern, jeweils mit neu berechnetem Signatur/Key-Paar.
**Innerhalb jedes Spends** ist das Paar für beide Prüfungen identisch.
Das widerlegt die Gleichheitsbehauptung für freie Paare, nicht den
festen `r=s=1`-Baustein. Die Algebra ist im Repository bereits aus Point-Locks
bekannt; hier wird sie auf diese Covenant-Abkürzung angewendet.
[Details](legacy_binding_findings.md), [Vektorgenerator](legacy_same_signature_counterexample.py).

## 3. Was die weiteren Suchen ausschließen

- **Zwei gleich große direkte Hashpfade:** Selbst mit dem günstigeren DER-Prädikat,
  idealisiert einem Entropiebit pro optionalem Hashschritt und ganz ohne
  sonstige Prüfkosten erlauben 201 Legacy-Opcodes höchstens zwei 25-Bit-
  Suffixe. Der Suchkostenexponent bleibt mindestens ungefähr `65.85`.
  Gemeinsame Präfixe beseitigen diese Schranke für diese Pfadfamilie nicht.
  Die spätere feste-erste-Nonce-Konstruktion fällt nicht in diese Familie.
  [Modell und Einschränkungen](two_hit_native_predicates.md).
- **Parameteränderungen der bestehenden ColliderScript-Brücke:** Im
  idealisierten 160-Bit-Modell mit getrennten 20-/64-Byte-Eingabedomänen gilt
  für insgesamt Q Abfragen `Pr[Treffer] <= Q^2/2^162`. Unter `2^64` Abfragen
  ist die Erfolgswahrscheinlichkeit kleiner als `2^-34`, wenn Setup mitgezählt
  wird. Das ist eine Schranke dieser Brückenklasse, kein Beweis über SHA-1
  oder sämtliche Covenants. [Herleitung und geprüfte Kryptanalyse](bridge_alternatives.md).

Eine neue Konstruktion müsste die native Relationsprüfung ändern,
einen wesentlich kompakteren gemeinsamen Nonce-Test liefern oder eine
passende strukturelle Abkürzung für die eingeschränkten Hash-Eingaben finden.
Keine dieser drei Lücken ist durch diese Untersuchung geschlossen.

## Konsensprüfung und Kosten der ausgeführten Vektoren

[Runner](core_gate_check.py) und [vollständiger Bericht](core_gate_check.json)
verwenden Bitcoin Core **30.3**, Commit
`49faec4f87f5cd19c88db01a82e5c68b087c8227`. Das offizielle Release-Archiv wird
gegen den Repository-SHA256-Pin geprüft. Jeder Lauf erzeugt eine frische
Regtest-Chain ohne Wallet und ohne Netzwerk-Peers. Alternative Spends desselben
Outpoints werden durch lokale Blockinvalidierung separat geprüft.

Alle **11 Erwartungen** bestanden: sieben Konsensannahmen, vier
Konsensablehnungen; Standard-Relay lehnte alle elf ab. Die negativen Fälle
umfassen mutiertes Preimage, falsches DER-Tag, negativen r-Wert und leere
Signatur. DER-kodiertes `r=0` sowie ein undefiniertes Sighashbyte werden vom
Parser erwartungsgemäß akzeptiert. Diese sind keine gültigen ECDSA-Signaturen.

| Positiver Fall | Redeemscript | scriptPubKey | scriptSig | Spendgewicht | Daten bei Redeemscript-Eintritt | Hint-Items | Stackmaximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Hash-to-DER, bekanntes Preimage | 4 B | 23 B | 22 B | 416 WU | 1 | 0 | 3 |
| Parser mit 32-Byte-Längenprüfung | 7 B | 23 B | 41 B | 492 WU | 1 | 0 | 3 |
| Zwei ECDSA-Kontexte, freies Paar | 4 B | 23 B | 111 B | 772 WU | 2 | 0 | 4 |

**Boundary:** `complete-transaction:` je ein P2SH-Input, ein P2WPKH-Output,
scriptSig einschließlich Redeemscript, Gebührenbetrag 10.000 Satoshi; die
Funding-Transaktion ist nicht im Spendgewicht enthalten. Keine Witness-
Serialisierung, da sämtliche Spends Legacy-Transaktionen sind: **0 Witness-
Bytes**, keine Annex-/Taproot-Budgets. Alle Daten liegen bei Eintritt vor;
scriptSig enthält zusätzlich einen Push des Redeemscripts. Es gibt in allen
Fällen genau **0 Hilfs-Hint-Items**. Das angegebene Stackmaximum zählt Main-
plus Altstack einschließlich der P2SH-Hülle und wurde am Bytecode hergeleitet,
nicht durch Core instrumentiert. Altstack bleibt leer.

Das Redeemscript führt im Erfolgsfall jeweils 3, 4 bzw. 4 Nicht-Push-Opcodes
aus; die P2SH-Hülle fügt zwei hinzu. Diese exakten rohen Konsens-Testvektoren
sind keine optimierten Messungen eines Repository-Scriptgenerators.
Core erzwingt sämtliche anwendbaren Konsensregeln. Der Tapscript-Executor des
Repositories und seine stack-unbegrenzten Hilfsfunktionen werden nicht benutzt.
Die positiven Parservektoren sind `locally-reproduced` / `consensus-validated`;
das ECDSA-Gegenbeispiel ist nach unabhängiger Gleichungs- und Core-Prüfung
`differentially-validated` / `consensus-validated`. Keine dieser Klassen ist
eine Covenant-Sicherheitsgarantie.

Reproduktion aus dem Repository:

```sh
python3 research/covenant-2026-09-17/legacy_same_signature_counterexample.py
python3 research/covenant-2026-09-17/core_gate_check.py --download-core
python3 tools/kb.py validate
```

Der erste Lauf des Core-Runners benötigt Internetzugriff auf das gepinnte
Release, spätere Läufe nur einen lokalen RPC-Port. Die Artefakte verändern
keine echten UTXOs. Bibliothekscode und bestehende Primitive-Metriken wurden
nicht geändert; Feldarithmetik-Tests wurden nicht ausgeführt.
