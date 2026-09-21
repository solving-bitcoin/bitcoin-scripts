# Zweite Suche: native Signaturrelationen und Transaktionsstruktur

**Ergebnis:** Auch diese Runde liefert noch keinen geheimnisfreien
Exact-Output-Covenant unter `2^64` ehrlicher Gesamtarbeit. Die Anforderungen
aus der [Hauptnotiz](README.md) bleiben unverändert. Die Untersuchungen verwenden
öffentliche Skalare und ausschließlich neu erstellte lokale Regtest-UTXOs.

Neu sind ein konkreter nativer Signaturzyklus, zehn Strukturtests und eine
exakte Untersuchung von Signaturlängen als Hash-Fingerabdruck. Die positiven
Core-Ergebnisse belegen die hier beschriebenen Bausteine und Gegenbeispiele;
sie belegen keine Covenant-Konstruktion.

## Ein Signaturzyklus ist noch kein schwieriges Summenproblem

Der konkrete Vorschlag verbindet acht frei gelieferte Public Keys in einem
Zyklus. Jede Kante verwendet dieselbe Signatur zweimal: unter `P_i` für den
ALL-Digest `z_i,L` und unter `P_(i+1)` für `z_i,R`. Die 16 Prüfkontexte entstehen
durch CODESEPARATOR. Ein gemeinsamer kleiner Nonce `k=1/2` und
`r=x(G/2)` würden bei ausschließlich gegenüberliegenden Noncepunkten eine
alternierende Summenrelation zwischen den 16 Digests ergeben. Solche
Mehrlistenrelationen wären für günstigere Suchverfahren interessant.

Die native ECDSA-Prüfung erzwingt diese Vorzeichenwahl jedoch nicht. Mit
`P_i=d_i G` und dem relativen Noncevorzeichen `tau_i` gilt stattdessen

```text
d_(i+1) = tau_i*d_i + (tau_i*z_i,L - z_i,R)/r mod n.
```

Wählt man die acht Vorzeichen als `(+1,-1,-1,-1,-1,-1,-1,-1)`, ist ihr
Produkt `-1`. Die zusammengesetzte Gleichung lautet dann

```text
d_8 = -d_0 + C.
```

Der Zyklus schließt für **beliebige** Digestwerte durch `d_0=C/2`. Alle
anderen öffentlichen Skalare folgen aus der Rekursion, und
`s_i=(z_i,L+r*d_i)/k` ergibt die Signaturen. Low-S-Normalisierung erhält beide
Prüfungen; sämtliche Signaturen sind mit diesem r höchstens 60 Bytes lang.
Es wird kein Transaktionshash gesucht.

Der [ausführbare Versuch](second_pass_cycle.py) berechnet die 16 tatsächlichen
ALL-Digests einer festen Fundinginstanz, löst den Zyklus und vergleicht alle
Gleichungen mit vollständiger Core-Ausführung. **Beide Empfänger-Varianten
desselben finanzierten Outpoints bestehen alle 16 nativen Prüfungen ohne
Suchschleife.** Die Signaturen und Public Keys dürfen für die zweite Variante
neu berechnet werden; genau diese Freiheit war Teil des Vorschlags.
Die [gespeicherten Vektoren](second_pass_cycle.json) enthalten sämtliche
öffentlichen Skalare, Signaturen, Sighashes und Transaktionen.

Das r-Feld wird in diesem Script nicht eigenständig auf `x(G/2)` festgelegt.
Das schwächt das Gegenbeispiel nicht: Es verwendet tatsächlich dieses r und
würde auch eine zusätzliche perfekte r-Prüfung bestehen. Eine Größenprüfung
allein darf umgekehrt nicht als allgemeine Fixierung des r-Felds ausgegeben
werden. Es handelt sich um einen Ausschluss dieses freien Zyklus, nicht aller
nativen Signaturgraphen.

**Kosten:** `complete-transaction:` P2SH-Input, ein P2WPKH-Output, 10.000
Satoshi Gebühr; Funding ausgeschlossen. Exakter roher Redeemscript-Vektor
145 Bytes, scriptPubKey 23 Bytes, scriptSig 907 Bytes, Spend 3.964 WU,
0 Witness-Bytes. Redeemscript-Eintritt: acht Keys und acht Signaturen,
**16 Datenitems und 0 Hint-Items**; scriptSig hat zusätzlich den Redeemscript-
Push. Der kombinierte Stackpeak ist durch Inspektion **19**: 16 Poolitems,
Signaturkopie, OP_SIZE-Ergebnis und Vergleichskonstante. 96 Nicht-Push-
Opcodes im Redeemscript, 98 mit P2SH-Hülle; Altstack leer und Endstack sauber.
Core erzwingt die Konsensgrenzen; Peaks/Opcodezählung sind am Bytecode
hergeleitet. Standard-Relay lehnt beide Fälle ab. Evidenz
`differentially-validated`, Deployment der positiven Vektoren
`consensus-validated`.

## Zusätzliche Legacy-Ausführung und zusätzliche Inputs

Der [Strukturversuch](second_pass_structure.py) enthält zehn vollständige
Core-Fälle, [alle mit erwarteten Ergebnissen](second_pass_structure.json):

- 200 ausgeführte Nicht-Push-Opcodes im bare-Legacy-scriptSig und 201 im
  scriptPubKey sind zusammen erlaubt. Dieselbe ALL-Signatur bleibt aber
  gültig, wenn man die 200 Berechnungsoperationen durch das direkte Pushen
  ihres Ergebnisses ersetzt. Der feste Scriptteil authentifiziert den
  vorgeschalteten Bytecode dadurch nicht.
- P2SH verhindert diese Budgeterweiterung durch seine Konsensregel, dass
  scriptSig nur Pushes enthalten darf. Der entsprechende Endstack als reine
  Pushes besteht hier dagegen sowohl Konsens als auch Standard-Policy.
- Eine feste Signatur auf dem SINGLE-Bug-Digest kann in den getesteten
  Transaktionen die Position hinter einem anderen Input verlangen. Sie
  akzeptiert jedoch verschiedene zusätzliche Outpoints mit unterschiedlichen
  Programmen und verschiedene Empfänger. Damit ist das Programm eines
  vermeintlichen zweiten Verifiers nicht erzwungen.

Die Endstack-Ersetzung ist nur behauptet, wenn die direkte Push-Kodierung
selbst in die Konsensgrenzen passt; die konkreten Zwei-Item-Vektoren tun das.
Die SINGLE-Konstante sind die Digestbytes `01 00...00`; als big-endian
ECDSA-Skalar ist das `2^248`, nicht die Zahl 1.

Alle Strukturvektoren enthalten **0 Hint-Items und 0 Witness-Bytes**. Die
bare-Ausführungen übergeben zwei Datenitems an das feste Script und haben
kombinierten Peak 3; die P2SH-Hülle erhöht den Peak auf 4 und fügt den
Redeemscript-Push hinzu. Die SINGLE-Bug-Fälle haben leere scriptSigs und Peak
2 durch die im Script eingebetteten Signatur-/Key-Konstanten. Kosten und
Policy-Ergebnisse je Transaktion stehen im JSON. Kein Tapscript-Hilfsexecutor
und keine deaktivierten Konsensgrenzen werden benutzt.

## Signaturlängen und weitere mathematische Kandidaten

Die [Längenanalyse](second_pass_legacy.md) untersucht öffentliche Offset-Keys
bei festem G/2-Nonce und gemeinsamem Transaktionsdigest. Die möglichen
vollständigen Längenvektoren wachsen in dieser Familie nur linear mit der
Anzahl m der Keys: höchstens `64m`. Die exakte Partition des gesamten
Skalarraums ergibt für 32 gleichmäßig verteilte Keys **1.025 Vektoren**,
also höchstens rund zehn Bit Auswahlkapazität. Adaptive Abfragen derselben
Keymenge erhöhen diese Kapazität nicht. Dies ist ein Host-Modell,
`locally-reproduced` / `unclassified`, keine implementierte Introspektion.

Die [weitere Brückensuche](second_pass_bridge.md) prüft freie Schnorr-Nonces,
nachträgliche Key-Recovery, eine hypothetische 16-Punkte-Summe sowie zwei
Schnorr-Prüfungen derselben Signatur. Sie trennt die jeweiligen algebraischen
Gleichungen von fehlenden Script-Prüfungen, Funding-Abhängigkeiten und
Modellkostenschätzungen. Keiner dieser Kandidaten schließt die Output-Bindung.

## Reproduktion und Stand

Core **30.3**, Commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`, gepinntes
Release-Archiv wie in der Hauptnotiz. Alle zwölf neuen Core-Erwartungen
bestanden; neun Spends wurden im lokalen Konsens angenommen, drei verworfen.
Die 16 einzelnen Signaturgleichungen des Zyklus wurden zusätzlich in der
unabhängigen öffentlichen Kurvenrechnung geprüft.

```sh
python3 research/covenant-2026-09-17/second_pass_cycle.py
python3 research/covenant-2026-09-17/second_pass_structure.py
python3 research/covenant-2026-09-17/second_pass_legacy_lengths.py
python3 tools/kb.py validate
```

Der offene Punkt bleibt ein tatsächlich ausführbarer Bezug zwischen den
festgelegten Outputs und den nativen Signaturbedingungen. Zusätzliche
öffentliche Prüfungen erzeugen diesen Bezug nicht allein durch ihre Anzahl.
