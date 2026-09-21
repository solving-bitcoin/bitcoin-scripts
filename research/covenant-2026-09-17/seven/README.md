# Sieben parallele Suchrichtungen

Stand: 17. September 2026. Gesucht bleibt ein geheimnisfreier Covenant mit
exakt vorgegebenen Outputs, weniger als `2^64` ehrlicher Gesamtarbeit und
größerem Aufwand für unerlaubte Outputs, auch wenn der Ersteller sämtliche
Setup-Daten behält. **Keine vollständige Konstruktion gefunden.** Diese Runde
liefert aber einen kompakteren nativen Zwei-Treffer-Baustein und korrigiert
damit eine Einschränkung der bisherigen Suche.

Die anschließend automatisiert fortgesetzte Suche wird im
[fortlaufenden Forschungsstand](../continuation/STATE.md) dokumentiert.

## 1. Der erste Nonce darf fest sein

Statt zwei gleich große Suchpfade vorzusehen, verwenden wir den festen ersten
Nonce `SHA256` und einen langen zweiten Hashpfad. Zunächst wird ein zulässiger
Transaktionskandidat gesucht, dessen öffentlich recoverbarer Public Key A
den ersten DER-Treffer liefert. Danach sucht man einen zweiten Treffer für
denselben A. Der zweite Pfad nutzt zwei Hashzustände und pro Auswahl nur

```
OP_2 OP_ROLL OP_ROLL H_i
```

Der vollständige **native A-Baustein** einschließlich fester ALL-Signatur,
zweier DER-Gates, exakter Anfangstiefe und abschließender Digest-Ungleichheit
hat als roher Testvektor **273 Bytes und 199 gezählte Opcodes**. Er bietet
`76,414,578,004,274,613` verschiedene zweite primitive Hashwörter, also etwa
**56,08 Bit**. Die Zählung entfernt insbesondere die Aliase
`HASH256 = SHA256; SHA256` und `HASH160 = SHA256; RIPEMD160`.

Genau **60 Kontroll-Hint-Items und ein Public-Key-Datenitem** liegen anfangs
vor; das kombinierte Stackmaximum ist nach Bytecode-Inspektion 64. Die feste
Anfangstiefe und die Ablage des ersten Digests auf dem Altstack sind notwendig:
Ein letzter freier Index dürfte sonst fremde Daten unter den Hashzuständen
auswählen. Die Signaturprüfung erzwingt einen gültigen, langen Public Key.

Bei `p = 780555/2^65` benötigt die idealisierte erste Phase ungefähr `1/p`
Transaktionskandidaten samt Public-Key-Recovery. Die zweite Phase benötigt
höchstens etwa `85/p = 2^51.84` primitive Hashaufrufe, zuzüglich Auswahl- und
Verwaltungskosten. Es wird keine riesige vorberechnete Tabelle vorausgesetzt.
Diese Schätzung ersetzt weder eine Messung der Recovery-Kosten noch eine
vollständige Covenant-Kostenanalyse.

**Noch fehlt die B-Seite:** Dieselben Nonces müssen auf einer tatsächlich
geprüften Darstellung der erlaubten Outputs ausgewertet werden. Der native
A-Baustein allein ist für beliebige Outputs lösbar. Seine zwei Treffer sind
deshalb kein Covenant. Ein vollständiger PoW-Zeuge wurde nicht berechnet.
[Herleitung, Generator und Grenzen](search1_nonce_encoding.md).

Die frühere `2W−25`-Schranke bleibt eine Aussage über die damals betrachteten
zwei gleich großen direkten Pfade. Sie darf nicht mehr als Ausschluss jedes
nativen Zwei-Treffer-Bausteins unter 201 Opcodes verwendet werden.

## 2. Native Digest-Gleichheit durch vollständige Recovery-Mengen

Für die feste Signatur `r=s=1` existieren nur die Noncepunkte `±lift(1)`;
`n+1` liftet nicht. Zwei verschiedene, kanonisch komprimierte Public Keys,
die beide diese Signatur für z bestätigen, müssen die beiden Recovery-Zweige
ausschöpfen. Daher gilt `P+Q = −2zG`. Werden dieselben zwei Keys mit derselben
Signatur in einem zweiten Kontext geprüft, folgt **z'=z modulo n**.

Das behebt den früheren Gegenbeweis gegen Gleichheit bei einem frei gewählten
Signatur/Key-Paar. Es liefert weiterhin keinen nativen Kontext, in den sich
ein arithmetisch geprüfter Soll-Output einsetzen ließe. Die Variante mit vier
Recovery-Keys für `r=2` behandelt auch beide X-Koordinaten `r` und `r+n`.
[Gleichungen, vollständige Vorzeichenanalyse und OpenSSL-Prüfung](search3_native_algebra.md).

## 3. Die sieben Teilaufgaben

| Suche | Ergebnis |
| --- | --- |
| [1: Nonce-Kodierung](search1_nonce_encoding.md) | Fester erster Nonce und Drei-Opcode-Routing beseitigen das isolierte native Platzproblem. |
| [2: Native Kontexte](search2_native_context.md) | Bei gleicher Output-Anzahl hängt exakte Gleichheit gewöhnlicher Legacy-Preimages nicht von Output-Beträgen oder -Scripts ab; 36.864 Kontexte geprüft. |
| [3: Native Algebra](search3_native_algebra.md) | Recovery-Mengen erzwingen skalare Digest-Gleichheit; zusätzliche Key-Zyklen liefern echte, aber noch nicht outputgebundene Bedingungen. |
| [4: Öffentliche Beweise](search4_public_bridge.md) | Öffentliche Garbling-Labels und statische Indexrelationen ersetzen keine verpflichtende Prüfung der erlaubten Transaktion. |
| [5: Funding und Formate](search5_funding_formats.md) | Die untersuchte Legacy/BIP143-Preimage-Überlappung verlangt bereits vor den Outputs einen selbstabhängigen 256-Bit-Hash-Treffer. |
| [6: Related Work](search6_related_work.md) | ColliderScript, ColliderVM, Binohash und QSB samt Versionen und Kombination geprüft; HORS-Autorisierung ist von Digest-Kollisionsresistenz zu trennen. |
| [7: Unabhängige Synthese](search7_synthesis.md) | Explizite Austauschbarkeit eines optionalen Taproot-Verifiers; Hashpfad-Korrelationen verlangen eine Analyse des gesamten adaptiven Transkripts. |

Alle sieben angeforderten Subagents wurden gestartet, gestaffelt entsprechend
den verfügbaren drei parallelen Agent-Slots. Die Hauptaufgabe hat die neuen
Bausteine unabhängig gegen Bitcoin Core geprüft.

Die siebte Suche zeigt außerdem an einer vollständig ausgezählten kleinen
Zufallsfunktion: Verschiedene Hashwörter sind nicht automatisch unabhängige
Prädikatsabfragen. Ein späterer Sicherheitsbeweis muss interne Hashkollisionen,
alle verworfenen Transaktionskandidaten und die Konditionierung auf den ersten
Treffer einbeziehen. Eine unveränderte Übernahme der idealen K2,2-Schranke
wird für die konkrete Konstruktion hier nicht behauptet.

## 4. Neue Core-Prüfungen

[Runner](core_fragments.py), [vollständige Transaktionen und Ergebnisse](core_fragments.json).
Bitcoin Core 30.3, Commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`,
offizielles Archiv anhand des Repository-Pins geprüft. Frische lokale
Regtest-Chain ohne Wallet oder Netzwerk-Peers; keine echten UTXOs.

**Alle 18 Erwartungen bestanden:** neun Konsensannahmen und neun Ablehnungen.
Die acht Routing-Vektoren bestehen zusätzlich die Standard-Policy. Sie
enthalten einen direkten Vergleich mit dem erwarteten Hashwert und lassen
die beiden DER-PoW-Gates sowie die native Root-Bindung ausdrücklich weg.
Damit wird die Stack-/Hashpfad-Ausführung geprüft, kein PoW-Erfolg vorgetäuscht.

| Positiver Vektor | Redeemscript | scriptSig | Gewicht | Datenitems am Eintritt | Hint-Items darin | Stackmaximum | Redeem-Opcodes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Routing mit beobachtbarem Hashresultat, 8 Varianten | 281 B | 378 B | 1.848 WU | 61 | 60 | 63 | 186 |
| Zwei Recovery-Keys, vier Prüfungen im selben Kontext | 75 B | 144 B | 904 WU | 2 | 0 | 5 | 22 |

`complete-transaction:` jeweils ein P2SH-Input, ein P2WPKH-Output und
10.000 Satoshi Gebühr. Das 23-Byte-P2SH-scriptPubKey liegt im Funding;
Funding-Gewicht ist ausgeschlossen. Sämtliche Daten und Hints koexistieren
bei Eintritt. scriptSig enthält jeweils zusätzlich einen Redeemscript-Push
(62 bzw. 3 Pushes). Die Legacy-Witness-Serialisierung ist **0 Bytes**.
Stackmaxima zählen Main- und Altstack einschließlich P2SH-Hülle, durch
Hostmodell/Inspektion ermittelt. Die Hülle hat zwei weitere Opcodes in ihrer
separaten Ausführung. Es handelt sich um rohe Konsens-Testvektoren, nicht um
optimierte Repository-Primitivmessungen.

Negative Routing-Fälle: Auswahl außerhalb der beiden Zustände am Anfang,
in der Mitte und am Ende; zusätzliches oder fehlendes Eingabeitem; falscher
Root. Negative Recovery-Fälle: doppelte Keys, falsche Keylänge und ein durch
CODESEPARATOR veränderter zweiter Kontext. Der positive Recovery-Vektor
scheitert an Standard-Policy wegen `Signature is found in scriptCode`.

Evidenz dieser Vergleiche: `differentially-validated`. Positive Routing-
Vektoren: `policy-validated`; positiver Recovery-Vektor: `consensus-validated`.
Der vollständige 199-Opcode-PoW-Kandidat bleibt `unclassified`. Kein
Tapscript-Executor und keine deaktivierten Konsensprüfungen wurden benutzt.

## 5. Verbleibende konkrete Aufgabe

Benötigt wird ein vollständiger Verifier für

```
NativeDigest(T_actual, D)
AND VerifyAll(shared_root, openings, funding_context, O*, D).
```

Die zweite Zeile muss zwingend ausgeführt werden und dieselben gebundenen
Daten verwenden. ColliderVMs gemeinsamer Root, Binohashs lesbarer Digest und
QSBs feste ALL-Signatur liefern Teile dieser Aussage. Die neue Nonce-Kodierung
verbessert den nativen Teil. Keiner dieser Bausteine liefert allein die
verpflichtende Gesamtprüfung bei behaltenem Erstellerzustand.
