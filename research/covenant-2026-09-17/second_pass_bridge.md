# Zweite Brückensuche: freie Nonce-Punkte und native Gruppenrelationen

Stand: 17. September 2026. Frage: Gibt es außerhalb der bisherigen
Zwei-Treffer-Hashpfade eine konkrete geheimnisfreie Bindung exakter Outputs
mit weniger als `2^64` ehrlicher Gesamtarbeit?

Diese Runde prüft vier mathematische Kandidaten. Keiner erfüllt derzeit die
Anforderungen. Es handelt sich um eigene Herleitungen mit Evidenz `inspected`,
Deployment `unclassified`, nicht um neue ausführbare Primitive. Aufwandangaben
sind idealisierte Schätzungen in den jeweils genannten Einheiten; keine
Onchain-Größen- oder Konsensbehauptung wird daraus abgeleitet.

## A. Freies R in Schnorr statt R = G

**Konkreter Kandidat:** Wähle einen öffentlich bekannten Signierschlüssel
`P = dG`, lasse `R = kG` frei variieren und suche eine SHA-1-Kollision zwischen
nativen Signaturen `sigma = bytes32(x(R)) || bytes32(s)` und arithmetisch
reproduzierbaren Tester-Nachrichten. Die Hoffnung ist, die zusätzlichen
256 Nonce-Bits für die bekannten strukturellen SHA-1-Angriffe zu nutzen.

Für gerade `P,R` verlangt BIP340

```
e = H_challenge(bytes32(x(R)) || bytes32(x(P)) || m) mod n
s = k + e*d mod n.
```

Dabei ist `m` der echte Bitcoin-Sighash. Für gewählte `k,m` ist eine gültige
Signatur leicht berechenbar. Das heißt aber nicht, dass ein SHA-1-Angriff
anschließend ihre 64 Bytes frei verändern darf.

Fixiert man durch einen Kollisionsalgorithmus bereits die gewünschten Bytes
`r,s` und kennt einen passenden Nonce-Skalar `k`, müsste man

```
H_challenge(r || x(P) || m) = d^-1*(s-k) mod n
```

erfüllen. Einfaches Transaktionsgrinding gegen diesen vorgegebenen Skalar
kostet in einem idealen Challenge-Modell ungefähr `2^256` Abfragen; dies ist
die Kostenanalyse genau dieser Umkehrstrategie, keine allgemeine Schranke
für strukturierte Angriffe. Ist stattdessen nur `R = lift_x(r)` aus dem
Kollisionsalgorithmus bekannt, fehlt außerdem `k = log_G(R)`. Die Tatsache,
dass ein zufälliges `r` ungefähr mit Wahrscheinlichkeit 1/2 ein gültiges
Kurven-X ist, liefert den Nonce-Skalar nicht.

Signiert man immer zuerst korrekt und behandelt die so erzeugten 64 Bytes als
Hashkandidaten, bleibt im idealen SHA-1-Modell die bereits dokumentierte
160-Bit-Kreuzkollisionsschranke bestehen. Freies `R` erweitert den Eingaberaum,
verkürzt aber keine Hashausgabe.

**Funding-Test:** Bei vorher festem `P` und unverändertem Leaf ist dieser
Kandidat nicht schon wegen Funding-Selbstreferenz kaputt. Seine ungeschlossene
Stelle ist ein struktureller SHA-1-Algorithmus für *berechenbar signierbare*
64-Byte-Nachrichten, nicht fehlende Nonce-Entropie. Es wurde kein solcher
Algorithmus mit Gesamtaufwand unter `2^64` gefunden.

## B. Den Public Key passend zur Kollisionssignatur recovern

### B1. BIP340-Recovery ist ein anderer Fixpunkt

Für eine bereits gewählte Schnorr-Signatur `(r,s)` und eine Nachricht `m`
ließe sich ohne Key-Prefixing formal `P = e^-1(sG-R)` setzen. In BIP340 ist
aber gerade

```
P(e) = e^-1*(sG-R)
e = H_challenge(r || x(P(e)) || m) mod n.
```

Beide Gleichungen müssen gleichzeitig gelten, einschließlich der kanonischen
geraden Y-Koordinate von `P`. Das ist keine direkte Public-Key-Recovery.
Einfaches Durchprobieren von `e` trifft in einem idealen Challenge-Modell nur
mit ungefähr `1/n` pro Versuch. Eine generische Zyklussuche findet beliebige
Zyklen der Abbildung, nicht notwendig einen für die Signatur erforderlichen
Fixpunkt. Für diese Strategie ist deshalb keine `2^128`-Birthday-Abkürzung
begründet, geschweige denn eine unter `2^64`.

Die verwendeten Signaturgleichungen und das Key-Prefixing sind durch
[BIP340 am Commit `24e96e870fffaa257b465ce1f0370c14aac588e8`](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0340.mediawiki)
festgelegt. Die Kosten- und Funding-Folgerungen hier sind eigene Analyse.

### B2. ECDSA-Recovery funktioniert, beseitigt aber die Output-Bindung

Für ECDSA `(r,s)`, einen zulässigen Punkt `R` mit `x(R) mod n = r` und den
Digest `z(T)` gilt tatsächlich

```
P(T) = r^-1*(sR-z(T)G).
```

Dies ist die Public-Key-Recovery aus
[SEC 1: Elliptic Curve Cryptography, Version 2.0, §4.1.6](https://www.secg.org/sec1-v2.pdf).
Damit lässt sich eine vorgegebene zulässige Signatur unter einem entsprechend
gewählten Public Key an praktisch jede Transaktion anpassen.

**Ersteller-Replay:** Wenn `P` frei aus dem Witness stammt, berechnet der
Ersteller für dieselbe vorgegebene Signatur und beliebige unerlaubte Outputs
schlicht `P(T_bad)`. Das spart Arbeit für beide Seiten. Eine bereits geminte
SHA-1-Kollision der Signaturbytes würde dabei weiterverwendet; der Angreifer
müsste nicht einmal eine neue Kollisionssuche bezahlen.

**Funding-Test:** Fixiert man `P` oder seinen Hash im Funding-Script, hängt
`z(T)` wieder vom Funding-Outpoint und damit vom gerade geänderten Commitment
ab. Mit `c = HASH160(P)` in einer entsprechenden festen Adresskonstruktion
landet man schematisch bei

```
c = HASH160(r^-1*(sR-z(T(Funding(c)), O*)G)).
```

Das ist ein diagonaler Fixpunkt. Eine Kollision zweier separat berechneter
Listen löst ihn nicht. Im idealisierten 160-Bit-Fixpunktmodell hat bloßes
Probieren etwa `2^160` Aufwand. Die genaue reale Abbildung ist kein bewiesenes
ideales Orakel; die Gleichung zeigt hier die fehlende Konstruktion, nicht
einen allgemeinen Unmöglichkeitsbeweis.

## C. Ein expliziter 16-Listen-Kandidat über ECDSA-Public-Keys

**Mathematischer Kandidat:** Sei `r = x(G) mod n`. Prüfe in 16 nativen
ECDSA-Kontexten jeweils die feste ALL-Signatur `(r,s=1)` unter einem
Witness-Public-Key `P_i`. Für einen ausgewählten Recovery-Zweig gilt

```
P_i = r^-1*(1-z_i)G.
```

Wäre zusätzlich folgende Gruppengleichung nativ prüfbar,

```
sum_i P_i = Q_C,  Q_C = r^-1*(16-C)G,
```

dann würde dieser Zweig die skalare Aussage `sum_i z_i = C mod n` liefern.
Die alternative Recovery mit `R=-G` muss eine tatsächliche Konstruktion
zusätzlich behandeln; sie ist hier nicht stillschweigend ausgeschlossen.

Falls jeder `z_i` aus einer unabhängig wählbaren Liste zufälliger Skalare
stammte, wäre das genau die Art additiver Relation, für die
[Wagners Verfahren, CRYPTO 2002](https://people.eecs.berkeley.edu/~daw/papers/genbday.html)
interessant ist. Eine grobe Abschätzung der erzeugten Listenelemente lautet
`k * 2^(256/(1+log2(k)))`:

| Listen | Elemente pro Liste | Gesamtzahl Elemente, ohne Zusatzkosten |
| --- | --- | --- |
| 4 | `2^85.333` | `2^87.333` |
| 8 | `2^64` | `2^67` |
| 16 | `2^51.2` | `2^55.2` |
| 32 | `2^42.667` | `2^47.667` |

Dies sind weder fertige Laufzeitbelege für einen konkreten Modulo-`n`-Solver
noch Bitcoin-Kostenmessungen. Sie erklären, warum die Relation mathematisch
interessant wäre. Drei unabhängige Fehler verhindern die Instanziierung:

1. **Keine native Public-Key-Summe:** `CHECKSIG`, `CHECKMULTISIG` und
   `CHECKSIGADD` prüfen einzelne Signaturen bzw. zählen Ergebnisse. Sie prüfen
   nicht die behauptete Summe beliebiger Witness-Punkte. Die arithmetische
   Auswertung dieser Punkte bräuchte erneut deren Bindung an die rohen Keys.
2. **Eine Aggregatsignatur ersetzt die Summenprüfung nicht:** Ein zusätzliches
   `CHECKSIG` unter `Q_C` bindet die vorigen `P_i` nicht an `Q_C`. Hier ist
   sogar `log_G(Q_C) = (16-C)/r mod n` öffentlich. Jeder Ersteller kann deshalb
   die zusätzliche Signatur unabhängig von der behaupteten Summe herstellen.
   Ein NUMS-Aggregatpunkt beseitigt diese bekannte Signiermöglichkeit, lässt
   aber den benötigten Zielskalar `C` für das skalare Listenproblem unbekannt.
3. **Keine 16 unabhängig auswählbaren Digest-Listen:** Bei festem Funding und
   einer gemeinsam variierten Transaktion entsteht pro Versuch ein gesamter
   16-Tupel von Digests. Seine Summe ist wieder ein einzelner zufälliger
   Skalar. Wagner benötigt unabhängig kombinierbare Listenelemente. Separate
   `CODESEPARATOR`-Kontexte allein liefern diese Kombinierbarkeit nicht.

**Ersteller-Replay:** Selbst nach Lösung dieser drei Probleme würde ein für
jede Output-Liste gleich gut lösbares Summenpuzzle noch keinen Covenant
liefern. Erforderlich wäre zusätzlich eine onchain erzwungene Asymmetrie
zwischen der arithmetisch erlaubten Transaktion und den tatsächlichen Outputs.
Ein öffentliches `C`, ein bekannter Aggregatschlüssel und behaltene
Signierschlüssel schaffen diese Asymmetrie nicht.

## D. Dieselbe Schnorr-Signatur als native algebraische Relation

Hier existiert eine wirklich native Relation. Lasse dieselbe vollständige
Schnorr-Signatur `(r,s)` unter zwei festen Public Keys `P1=aG`, `P2=bG` in zwei
Kontexten prüfen. Da BIP340 den Punkt `R` aus `r` eindeutig mit geradem Y
bestimmt, folgt

```
sG = R + e1*aG = R + e2*bG
also a*e1 = b*e2 mod n.
```

Anders als ein hypothetisches Additionsopcode benutzt diese Prüfung nur zwei
native Signaturprüfungen. Sie ist aber eine volle 256-Bit-Gleichheit. Bei
festen unterschiedlichen Schlüsseln/Kontexten und je einem neuen gemeinsamen
`R` kostet direktes Grinding im idealen Challenge-Modell ungefähr `2^256`
Versuche. Mit identischen Keys und identischen Kontexten ist sie tautologisch
und bindet keine vorgegebenen Outputs. Durch zusätzliche Prüfungen derselben
Signatur entstehen weitere Gleichheiten, keine frei wählbare `k`-Summenrelation.

Wenn man stattdessen nach Kenntnis einer festen Transaktion zwei freie Keys
suchen darf, kollidiert die Funktion `a -> a*H(r||x(aG)||m)` generisch nach
ungefähr `2^128` Versuchen; die kanonischen Y-Vorzeichen sind einzurechnen.
Das liegt bereits über dem Budget. Diese zwei Keys erst danach ins Funding
aufzunehmen änderte außerdem die signierte Transaktion.

## E. Lange Signaturcontainer helfen den Kandidaten A/B nicht

Die bekannten praktischen SHA-1-Kollisionsverfahren benötigen kontrollierbare
Datenblöcke. Die in
[Leurent/Peyrin, USENIX Security 2020, §2.2.1 und §1.1](https://www.usenix.org/system/files/sec20-leurent.pdf)
beschriebenen Verfahren bieten keine passende frei signierbare 64-Byte-
Nachrichtenfamilie. Freies `R` ändert diese Tatsache nicht automatisch.

Bitcoin akzeptiert in den betreffenden nativen Signaturprüfungen keine
beliebig angehängten Kollisionsblöcke: Tapscript-Signaturen haben 64 bzw.
65 Bytes; gültige Legacy-ECDSA-Signaturen einschließlich Hash-Typ höchstens
73 Bytes. Das reicht nicht für zwei frei kontrollierbare 64-Byte-Datenblöcke.
Ein zweiter SHA-1-Kompressionsblock aufgrund des Paddings ist kein zweiter
frei kontrollierbarer Datenblock.

Auch ein langer Dummy im Witness oder in `CHECKMULTISIG` wird dadurch nicht
zum transaktionsgebundenen Kollisionscontainer. Ein Dummy außerhalb der
Signaturprüfung besitzt keine entsprechende Bindung; ein tatsächlich zu
prüfendes Signaturargument unterliegt der strikten DER-Prüfung. Eine
fehlgeschlagene Multisig-Prüfung mit `OP_NOT` beweist nicht, dass ein bestimmtes
Teilargument eine gültige ALL-Signatur war.

Die überprüften Format- und Opcode-Grenzen stehen in
[Core `49faec4f87f5cd19c88db01a82e5c68b087c8227`, interpreter.cpp](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp).
Diese Argumente verwerfen die konkreten Containerwege; sie sind keine
vollständige Klassifikation aller denkbaren Script-Programme.

## Ergebnis dieser Runde

Der neue konstruktive Ansatz C hat eine konkrete günstige algebraische
Suchgleichung, scheitert jedoch an einer nicht vorhandenen nativen Relation,
unbegründeter Unabhängigkeit der Suchlisten und zusätzlich fehlender
Output-Asymmetrie. Ansatz D liefert eine echte native Gruppenrelation, bleibt
aber quantitativ weit außerhalb des Budgets. Freies `R` eröffnet zusätzliche
Signaturkandidaten, ohne bislang einen passenden SHA-1-Angriff bereitzustellen.

Falsifizierbare nächste Schritte wären ein ausführbarer nativer Prüfer der
in C genannten Punktrelation samt unabhängigen Digest-Listen, oder ein
konkreter SHA-1-Kollisionsalgorithmus auf gültigen BIP340-Signaturen für eine
vorher fixierte Fundinginstanz. In beiden Fällen muss ein vollständiger
Ersteller-Replay für unerlaubte Outputs mitgerechnet werden.
