# R5: Tapscript als native Referenz für einen arithmetischen Verifier

Frage: Kann eine verpflichtende Tapscript-Ausführung die Legacy-DER-Brücke
ersetzen, so dass exakt vorgeschriebene Outputs bei behaltenem Erstellerzustand
mit weniger als `2^64` ehrlicher Gesamtarbeit durchgesetzt werden?

Diese Untersuchung prüft drei konkrete Ersatzvorschläge: aus
`CHECKSIGADD`-Ergebnissen gewonnene Abfragebits, eine lediglich gemeinsam
festgelegte Schnorr-Nonce und eine Tabelle vollständiger Signaturen. **Keiner
liefert die gesuchte Bindung.** Das sind abgegrenzte Ergebnisse; weder ein
allgemeiner Unmöglichkeitsbeweis noch eine erneute Prüfung der bereits
untersuchten Taproot-Tweak-Auslöschung.

Das deterministische [Host-Experiment](r5_tapscript_reference.py) erzeugt
[vollständige Ergebnisse](r5_tapscript_reference.json). Evidenz:
`locally-reproduced`; Deployment: `unclassified`. Es verwendet echte
secp256k1-Gleichungen und vollständig spezifizierte BIP341/342-Sighash-Preimages,
aber keine Bitcoin-Core-Ausführung. Der Vorfahr des Funding-Outpoints ist
synthetisch; eine existierende UTXO wird nicht behauptet. Ein kleines
Semantikmodell ist keine unabhängige Konsensvalidierung.

## 1. CHECKSIGADD erzeugt keine transaktionsbestimmten Zufallsbits

Für einen 32-Byte-Schlüssel gilt an der in Core untersuchten Grenze:

- Eine leere Signatur liefert falsch, ohne die Schnorr-Prüfung aufzurufen.
- Eine gültige nichtleere Signatur liefert wahr.
- Eine ungültige nichtleere Signatur bricht die Ausführung ab.

`CHECKSIGADD` addiert das Ergebnis zur gelieferten ScriptNum. Eine Folge
fehlgeschlagener Schnorr-Prüfungen kann daher keine im Script weiterverarbeitbare
Bitmap liefern. Die spezielle Behandlung unbekannter Schlüssellängen liefert
ebenfalls keine Transaktionsinformation. Diese Semantik steht in
[Core 30.3, `EvalChecksigTapscript` und `OP_CHECKSIGADD`, Commit
49faec4f87f5cd19c88db01a82e5c68b087c8227](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp#L322).

Der konkrete Gegenversuch legt acht Schlüssel mit den **öffentlichen und
behaltenen** Skalaren `1,...,8` in ein einziges Leaf:

```
OP_0
<P1> OP_CHECKSIGADD ... <P8> OP_CHECKSIGADD
OP_3 OP_NUMEQUAL
```

Der interne Taproot-Schlüssel ist der NUMS-Punkt aus BIP341. Der Gegenversuch
benutzt somit tatsächlich den Script-Path und benötigt keinen Key-Path-Bypass.
Es gibt nur dieses Leaf. Die geordneten Eingangsdaten sind
`sig8 ... sig1`; genau drei Signaturen sind nichtleer.

Für jeden der `binomial(8,3)=56` möglichen Teilmengenauswahlen wird ein Zeuge
berechnet, einmal für Output `(9000, OP_TRUE)` und einmal für
`(8000, OP_2)`, jeweils aus demselben Funding-Outpoint und mit demselben Leaf.
Alle 112 Fälle erfüllen die modellierten Signaturgleichungen und den
Schwellenwert. Je Transaktion werden acht Signaturen einmal erzeugt und
anschließend die 56 Teilmengen vollständig geprüft. Jede ausgewählte Signatur
ist eine 64-Byte-DEFAULT-Signatur.

Das Ergebnis ist stärker als ein einzelner anderer Spend: **Jede zulässige
3-aus-8-Abfrage ist für beide Output-Listen verfügbar.** Eine arithmetische
Prüfung, die ihre Prüfstellen ausschließlich aus diesen freiwilligen
Nichtleer-Bits gewinnt, erhält dadurch keine ehrliche Challenge. Wird ein
fester nichtleerer Signaturwert vorgeschrieben, entfällt dieses konkrete
Wiederholungssignieren; ein Fehlschlag liefert dann aber gerade kein Nullbit,
sondern einen Abbruch. Andere Beziehungen zwischen mehreren Signaturen sind
durch dieses Gegenbeispiel nicht ausgeschlossen.

Die Preimages folgen [BIP341 am Commit
24e96e870fffaa257b465ce1f0370c14aac588e8](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0341.mediawiki#common-signature-message)
und der [BIP342-Erweiterung am selben Commit](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki#common-signature-message-extension).
Beide Transaktionen verwenden DEFAULT, einen Input, keinen Annex und keinen
CODESEPARATOR. Der vollständige zu hashende SigMsg einschließlich Erweiterung
ist jeweils 211 Bytes; das Epoch-Byte kommt beim TapSighash hinzu.

Ressourcen des **rohen Grenzfall-Vektors**, ohne Repository-Compiler:

| Größe | Wert und Grenze |
| --- | --- |
| Leaf | 275 Bytes |
| Daten bei Script-Eintritt | 8 Signaturitems, davon 3 nichtleer |
| Zusätzliche Hint-Items | 0 pro Aufruf und 0 insgesamt |
| Gesamter Witness | 10 Items einschließlich Leaf und Control-Block |
| Serialisierter Witness | 513 Bytes einschließlich aller Längen |
| Kombinierter Stack-Peak | 10 Items, aus dem Layout abgeleitet |
| Ausgeführte Nicht-Push-Opcodes | 9, aus dem Layout abgeleitet |
| Verbrauchtes Signaturbudget | 150 Einheiten für 3 nichtleere Prüfungen |
| Komplette Spend-Transaktion | 759 WU im erzeugten Vektor |

Alle acht Datenitems existieren gleichzeitig beim Eintritt; der Altstack
bleibt leer. Der Peak berücksichtigt auch den anfänglichen Zähler und den
gerade gepushten Schlüssel. Diese Größen sind keine gemessenen
Interpreter-Metriken und keine Policy-Zusage.

## 2. Eine gleiche Nonce bindet noch nicht den arithmetischen Signaturwert

Die bestehende ColliderScript-Spezialisierung zeigt bereits, dass ein
vollständiger variabler Punktverifier nicht zwingend nötig ist. Für die
bekannten, geraden Punkte `P=R=G` genügt mathematisch

```
e(m) = H_BIP0340/challenge(x(G) || x(G) || m) mod n
s(m) = 1 + e(m) mod n.
```

Ein arithmetischer Verifier für den erlaubten Output kann also diesen
Skalar berechnen. Die offene Stelle ist dessen Gleichheit mit den **letzten
32 Bytes des tatsächlich nativ geprüften 64-Byte-Objekts**. Den Nonce-Punkt
allein festzulegen liefert diese Gleichheit nicht. Die zugrunde liegende
Signaturgleichung stammt aus [BIP340, gleicher unveränderlicher Commit](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0340.mediawiki#verification).

Das Experiment signiert die beiden oben erzeugten unterschiedlichen
TapSighash-Nachrichten mit `d=k=1`. Die beiden Signaturen haben exakt
denselben ersten 32-Byte-Teil. Beide akzeptieren in ihrem jeweiligen Kontext,
beide lehnen den anderen Kontext ab, und

```
s_good - s_bad = e_good - e_bad mod n
```

wird durch die unabhängige Skalarrechnung bestätigt. Ein Beweis über
`s_good` neben einer nativen Signatur mit `s_bad` bleibt daher trotz gleicher
Nonce ungebunden. Das Experiment setzt sogar die gewünschte gemeinsame
Nonce am Host durch; im realen Script muss auch diese Beziehung erst
erzwungen werden.

Wird stattdessen die **ganze** Signatur in beiden nativen Prüfungen
wiederverwendet, gilt `e_1 P_1 = e_2 P_2`; das ist die bereits dokumentierte
Relation aus [der zweiten Brückensuche](../second_pass_bridge.md#d-dieselbe-schnorr-signatur-als-native-algebraische-relation).
`CHECKSIGADD` erzeugt daraus weder eine Punktaddition noch Zugriff auf `s`.
Es gibt in dieser Untersuchung keinen neuen Solver für diese Gleichung.

## 3. Eine explizite Signaturtabelle wäre eine Bindung, ist aber zu klein

Ein konkreter vollständig bytegebundener Ersatz ist möglich: Für eine feste
Nonce `R=kG` und einen festen bekannten Schlüssel `P=dG` hinterlegt das Leaf
vollständige Konstanten `sigma_j = x(R)||s_j` und deren kleine arithmetische
Darstellungen. Die Auswahl eines Eintrags liefert dadurch wirklich dasselbe
Signaturobjekt auf der nativen und arithmetischen Seite. Das umgeht die
fehlende Konkatenation für diese endliche Menge.

Aber der feste native Challenge muss einen der Werte

```
E_j = d^-1 (s_j-k) mod n
```

treffen. Im ausdrücklich betrachteten Modell ist die Tabelle vor den
frischen Challenge-Abfragen festgelegt; andere Eingaben dürfen durch die
Transaktion variiert werden. Bei `M` verschiedenen Zielen besitzt jeder
Skalar höchstens zwei 256-Bit-Hash-Urwerte. Daher gelten für diese Strategie

```
Pr[Treffer je frischer Abfrage] <= 2M / 2^256
Pr[Treffer in Q frischen Abfragen] <= 2MQ / 2^256
E[Abfragen] >= 2^255 / M.
```

Das ist eine eigene Ideal-Orakel-Rechnung für die explizite feste Tabelle.
Sie behandelt weder einen kryptanalytischen Angriff noch jede adaptive
selbstreferenzielle Funding-Konstruktion als bereits bewiesen. Verschiedene
Nonce-Präfixe machen die einzelnen Abfragen nicht gleichzeitig für alle
Tabelleneinträge brauchbar; die Rechnung gewährt dem Kandidaten großzügig
weiterhin alle `M` Ziele je Abfrage.

Eine unmittelbar im Leaf liegende vollständige 64-Byte-Konstante kostet
mindestens 65 Script-Bytes. Selbst wenn man der Tabelle die **gesamten
4.000.000 WU eines Blocks** überlässt und allen weiteren Platzbedarf
ignoriert, passen höchstens 61.538 solcher Konstanten hinein. Damit ist die
erwartete Zahl frischer Challenge-Abfragen mindestens `2^239.09`; bei
`2^64` Abfragen beträgt die Erfolgsobergrenze ungefähr `2^-175.09`.
Die Blockgrenze folgt aus [Core, gleiche Revision,
`MAX_BLOCK_WEIGHT`](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/consensus/consensus.h).
Das 1.000-Item-Limit lässt sich bei einer Literal-Tabelle durch verzweigte
Auswahl grundsätzlich beachten; es ändert diese großzügige Bytegrenze nicht.

Auch eine idealisierte kompakt geöffnete **explizite Offchain-Tabelle** löst
das Gesamtarbeitsproblem nicht: Schon mit nur einer Arbeitseinheit pro
erzeugtem Eintrag ist für diese Suchstrategie

```
W >= M + 2^255/M >= 2^128.5.
```

Ein Taptree mit vielen unterschiedlichen Leaves bindet die jeweilige Auswahl
zusätzlich in den Sighash; er liefert keinen Beleg, dass die eben gewährte
gleichzeitige Suche gegen sämtliche Ziele effizient möglich wäre. Ein nach
Ermittlung des gewünschten `s` neu festgelegtes Leaf verändert seinerseits
den Funding- und Signaturkontext. Die vorliegende Rechnung ist keine
allgemeine Analyse solcher Fixpunkte.

## Offener Anschluss

Der präzisere konstruktive Bedarf ist eine Bindung des **variablen
32-Byte-Skalarteils** an einen bekannten Nonce-Präfix, ohne eine vollständige
Signaturtabelle aufzuzählen und ohne eine 160-Bit-Kreuzkollision. Ein neuer
Vorschlag muss genau diese Beziehung als ausgeführten Script-Prädikat angeben.
Frei gewählte Erfolgsbits oder ein gemeinsamer Nonce-Punkt erfüllen sie nicht.
Die bereits vorhandene große variable-Punkt-CSFS-Implementierung ist dafür
kein zwingender Ausgangspunkt: `P=R=G` reduziert die benötigte Algebra schon
auf Challenge-Hashing und Skalararithmetik, während die Bytebindung offenbleibt.

Reproduktion:
`python3 research/covenant-2026-09-17/continuation/r5_tapscript_reference.py`.
Keine Rust-Dateien, Primitivmetriken, Compilerregeln oder Feldarithmetik-Tests
wurden geändert bzw. ausgeführt.
