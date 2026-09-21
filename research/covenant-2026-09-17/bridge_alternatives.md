# Günstigere ColliderScript-Brücke: quantitative Suchgrenzen

Stand: 17. September 2026. Repository-Basis:
`ca207a94d03040463c78dcce04d0f0d14f06d20e`.

- **Frage:** Kann eine Variante der vorhandenen Big-/Small-Brücke einen
  geheimnisfreien Exact-Output-Covenant mit weniger als `2^64` ehrlicher
  Gesamtarbeit einschließlich Vorbereitung ergeben?
- **Vergleichsziel:** Gesamte Zahl der Hashauswertungen, unabhängig von
  Parallelität, Speicherreduktion und einer etwaigen Amortisierung.
- **Ergebnis:** Kein solcher Kandidat gefunden. Für die unten genau definierte
  Ideal-Orakel-Klasse liegt bereits die kollisionsbedingte Sucharbeit weit über
  dem Budget. Das ist kein allgemeiner Unmöglichkeitsbeweis für Covenants und
  ausdrücklich kein kryptanalytischer Beweis für SHA-1.
- **Evidenz:** Quellen `reported`; Konstruktionen und Herleitungen `inspected`.
  Keine neue Bitcoin-Script-Implementierung und keine gemessenen Scriptkosten.
- **Deployment:** `unclassified`.

## 1. Die Klasse, für die die Schranke gilt

Die korrigierte Brücke aus der Übergabe verlangt beim ehrlichen Spend

```
H(sigma(T, nonce)) = H(D.Gen(pi)),
len(sigma) = 64, len(D.Gen(pi)) = 20,
```

mit einem idealen `n = 160`-Bit-Orakel `H`. Die Längen trennen die syntaktischen
Eingabedomänen. Wiederholte Abfragen derselben Eingabe liefern keinen neuen
Versuch. Alle neuen Orakelabfragen zählen, einschließlich solcher aus Setup,
Tabellenerstellung, verworfenen Transaktionen und abschließender Prüfung eines
vorher nicht abgefragten Kandidaten.

Der Generator darf adaptiv sein und zuvor beobachtete Orakelwerte verwenden.
Sein zulässiger Ausgabebereich wird für die Schranke sogar vergrößert: Jeder
abgefragte 20-Byte-Eingabewert darf als potentieller Tester gelten, selbst wenn
seine gültige `D.Gen`-Öffnung noch fehlt. Auf der Signaturseite darf jeder
abgefragte 64-Byte-Wert als potentieller Kandidat gelten, selbst wenn er keine
passende Transaktionssignatur ist. Diese Lockerung hilft nur dem Suchenden.
Insbesondere zählen interne `H`-Abfragen auf 20-Byte-Pfadwerten ebenfalls mit.

Seien `q_f` und `q_g` vorab festgelegte Obergrenzen für verschiedene Orakel-
Eingaben beider Domänen. Dann gilt durch Vereinigung über domänenübergreifende
Paare

```
Pr[ein Treffer] <= q_f * q_g / 2^160.
```

Begründung: Beim ersten Offenlegen des später abgefragten Wertes eines Paares
ist dieser Wert, bedingt auf die gesamte bisherige Historie, gleichverteilt.
Die Wahrscheinlichkeit, den bereits bekannten Wert zu treffen, beträgt
`2^-160`. Adaptive Auswahl der neuen Eingabe ändert diese Eigenschaft des
idealen Orakels nicht. Wiederabfragen sind gerade keine neuen Werte.
Für eine adaptive Aufteilung mit einer festen Gesamtobergrenze `Q` zählt
man dieselben Paare bei ihrer ersten Offenlegung. Auf jedem Verlauf gibt es
höchstens `floor(Q^2/4)` Paare; somit gilt ebenfalls

```
Pr[ein Treffer mit insgesamt Q neuen Abfragen] <= Q^2 / 2^162.
```

Diese Argumentation setzt wirklich frische, verschiedenartige Eingaben und
ideale Ausgaben voraus. Sie gilt nicht, wenn identische Eingaben auf beiden
Seiten erlaubt sind, der benötigte Treffer durch bekannte Struktur bereits
feststeht, oder ein kryptanalytischer Angriff das Ideal-Orakel-Modell verletzt.

Konkrete Konsequenzen:

| Gesamtbudget `Q` | Obergrenze für Erfolg |
| --- | --- |
| `2^60` | `2^-42` |
| `2^64` | `2^-34` = etwa `5,82 * 10^-11` |
| `2^80` | `1/4` |

Die strenge Vereinigungsschranke verlangt für mindestens 50 % Erfolg
`Q >= 2^80.5`. Die übliche Poisson-Näherung für zwei feste, gleich große Listen
liefert `Q ≈ 2 sqrt(ln(2)) * 2^80 = 2^80.7356` für 50 % Erfolg. Der zweite Wert
ist eine Näherung für diese Suchstrategie, keine zusätzliche universelle
Untergrenze. Bereits die schwächere strenge Grenze überschreitet das Budget
um mehr als 16 Bits. Nicht-Hash-Arbeit und die Kosten von `D.Gen` kommen hinzu.

[ColliderScript, Fassung 15.11.2024, insbesondere §5.1](https://eprint.iacr.org/2024/1802)
verwendet entsprechend `q_f + q_g = 160`, wenn dort `q_f,q_g` die **Logarithmen**
der Listengrößen bezeichnen. Die dortigen etwa `2^86` Hashabfragen enthalten
weitere Pfad- und Kollisionssuchkosten. Eine bessere Speicher-/Pfadstrategie
kann diese Zusatzkosten senken; sie ändert die 160-Bit-Treffergleichung nicht.

## 2. Vorberechnete und adaptiv gewählte Tabellen

Eine bereits vorhandene Tabelle mit `M` Zielwerten erlaubt ungefähr
`2^160/M` frische Signaturversuche pro erwartetem Treffer. Für etwa `2^64`
Signaturversuche wäre somit `M ≈ 2^96` erforderlich. Schon die explizite
Erzeugung dieser Tabelle überschreitet das Gesamtbudget. Allein unkomprimierte
160-Bit-Ausgabewerte belegen `20 * 2^96 = 2^100.322` Bytes; Öffnungen und Indizes
sind darin nicht enthalten.

Ein Merkle-Root ersetzt weder Tabellenherstellung noch die Verifikation eines
nicht vertrauenswürdigen Tabelleninhalts. Tabellenkompression kann Speicher
und Onchain-Prüfung ändern, aber keine vorher unbekannten idealen Hashwerte
kostenlos liefern. Wird die Tabelle nach Kenntnis des Gewinners in das Leaf
aufgenommen, ändern sich dessen Commitment und gewöhnlich Funding-Outpoint
und Sighash; das ist die bekannte Selbstreferenz aus der Übergabe. Wird die
Tabelle vorher fixiert, greift die Trefferschranke einschließlich ihrer
Herstellung. Offchain-Prüfung des erlaubten Spends hebt diese Abhängigkeit
nicht auf.

## 3. Weshalb Wagner nicht unmittelbar passt

[Wagners Originalarbeit, CRYPTO 2002](https://people.eecs.berkeley.edu/~daw/papers/genbday.html)
behandelt `k` Listen mit einer **Summen- oder XOR-Gleichung**. Für vier Listen
über einem 160-Bit-Raum beträgt die bekannte Größenordnung pro Liste
`2^(160/3)`, insgesamt grob `4 * 2^(160/3) = 2^55.333` Listenelemente vor weiteren
Algorithmuskonstanten. Das wäre im richtigen Prädikat durchaus interessant.

Die benötigte Script-Aussage wäre aber beispielsweise

```
H(A1) XOR H(A2) XOR H(B1) XOR H(B2) = 0.
```

`OP_EQUAL` prüft stattdessen vollständige Bytengleichheit. Vier paarweise
hashgleiche Elemente sind kein Vier-Listen-XOR-Problem. Native Hashpfade bilden
auch keine frei auswertbare XOR-/Summenverknüpfung der rohen 160-Bit-Ausgaben.
`OP_XOR` ist im Legacy-/SegWit-v0-Interpreter deaktiviert; in Tapscript fällt
sein Byte unter die vorbehaltene OP_SUCCESS-Semantik, nicht unter eine nutzbare
XOR-Operation. Eine arithmetisch behauptete XOR-Summe über zerlegte Hashes
benötigt genau die bislang fehlende Bindung an die nativen Hashausgaben.

Die verfügbare Opcode-Semantik wurde gegen
[Bitcoin Core `49faec4f87f5cd19c88db01a82e5c68b087c8227`, interpreter.cpp](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp)
geprüft. Diese Aussage schließt andere, noch zu konstruierende native
Relationsprüfer nicht aus.

## 4. SHA-1 und RIPEMD-160: überprüfte Angriffsvoraussetzungen

[Leurent/Peyrin, USENIX Security 2020](https://www.usenix.org/system/files/sec20-leurent.pdf)
nennen `2^61.2` SHA-1-Äquivalente für identische Präfixe und `2^63.4` für
Chosen-Prefix-Kollisionen, hardwarebezogen auf GTX 970. §2.2.1 verwendet zwei
kontrollierbare Nachrichtenblöcke; die ausgeführte Chosen-Prefix-Kollision
verwendete einen partiellen Birthday-Block und neun Near-Collision-Blöcke.

Die konkrete ehrliche Signatur ist dagegen
`bytes32(x(G)) || bytes32((1+e(T,nonce)) mod n)`: Der erste 32-Byte-Teil ist
fest, der zweite durch den SHA-256-basierten Challenge-Wert bestimmt. SHA-1
verarbeitet dafür einen 64-Byte-Datenblock und einen festen Padding-Block.
Ein kontrollierbarer zweiter Datenblock steht nicht zur Verfügung. Die
20-Byte-Testerwerte bieten ebenfalls nicht die erforderlichen kontrollierbaren
Datenblöcke. Die genannten Kosten sind deshalb kein Algorithmus für die hier
benötigte eingeschränkte Kreuzkollision. Ein langes separates Witness-Element
hätte wieder keine nachgewiesene Bindung an die echte Signatur.

[Stevens/Karpman/Peyrin, ePrint 2015/967](https://eprint.iacr.org/2015/967)
behandelt eine Freestart-Kollision. Der frei wählbare Anfangszustand gehört
nicht zur Schnittstelle von `OP_SHA1`.

[Zhang et al., ePrint 2025/1531, Revision 12.09.2025](https://eprint.iacr.org/2025/1531)
erreicht 44 Schritte im Semi-Free-Start-Modell für RIPEMD-160. Das ist weder
vollständiges RIPEMD-160 mit 80 Schritten noch dessen festes natives IV.

Erneute Websuche am 17.09.2026 nach kurzen/einblockigen SHA-1-Kollisionen,
ColliderScript-Verbesserungen und neueren RIPEMD-160-Angriffen lieferte keinen
primären Beleg für einen passenden Algorithmus unter `2^64`. Dieser negative
Suchbefund ist keine Aussage, dass ein solcher Angriff mathematisch unmöglich
ist oder dass jede Veröffentlichung erfasst wurde.

## 5. Konkrete nächste Akzeptanzkriterien

Ein Fortschritt über diese Sackgassen hinaus muss mindestens eines liefern:

1. Einen nativen, an die echte Transaktion gebundenen Relationsprüfer mit
   kleinerer effektiver Entropie, dessen Gegenstück auf der arithmetischen Seite
   dieselben Daten und Nonces prüft. Bloß am Host verkürzte Hashes genügen nicht.
2. Einen wirklich passenden strukturellen Angriff auf die oben angegebenen
   kurzen Nachrichtenfamilien, einschließlich der Kosten, aus einer gewünschten
   `s`-Bytefolge eine gültige Transaktion mit unveränderten Outputs zu erzeugen.
3. Eine andere native algebraische Relation, die beispielsweise Wagners
   Listenverfahren ermöglicht, ohne eine unbewiesene Big-/Small-Bindung
   vorauszusetzen.

Bei allen drei Optionen muss der Ersteller den ehrlichen Algorithmus mit
unerlaubten Outputs wiederholen dürfen; behaltene Schlüssel, Preimages,
Tabellen und vorher gefundene Kandidaten sind Teil seines Zustands. Eine
Kollisionsschranke gegen nur einen veröffentlichten ehrlichen Digest genügt
nicht.
