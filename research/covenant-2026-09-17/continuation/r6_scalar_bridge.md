# R6: Hashgraphen als Brücke zum variablen Schnorr-Skalar

Frage: Kann die arithmetische Darstellung von `s` bei `P=R=G` an die
tatsächlich nativ geprüfte 64-Byte-Signatur gebunden werden, indem eine
kleine Checksumme, Hashketten oder viele wählbare Hashpfade die bisherige
20/64-Byte-Kreuzkollision ersetzen?

**Kein solcher Ersatz wurde gefunden.** Das neue Ergebnis ist eine begrenzte
Erweiterung des bisherigen Kollisionsarguments auf *adaptive Gleichheitsgraphen*
aus den vorhandenen nativen Hash-Opcodes. Es verhindert insbesondere, eine
exponentielle Anzahl möglicher Hashpfade als kostenlos verkürzten Digest zu
zählen. Es ist kein Unmöglichkeitsbeweis für Bitcoin-Covenants, native
Gruppenrelationen oder kryptanalytische Verfahren gegen konkrete Hashfunktionen.

Das [Host-Experiment](r6_scalar_bridge.py) und seine
[Ergebnisse](r6_scalar_bridge.json) haben Evidenz `locally-reproduced` und
Deployment `unclassified`. Die allgemeine Folgerung ist eine eigene
mathematische Analyse im unten definierten Idealmodell. Kein echter
Kollisionszeuge, vollständiger Covenant oder Core-Erfolg wurde erzeugt.

## 1. Konkreter kleiner Matcher

Ein wirklicher Script-Ausdruck für zwei alternative Pfade ist möglich.
Der Eintrittsstapel ist `a sigma path_bit`, wobei `a` eine kanonische
ScriptNum mit höchstens vier Bytes und `sigma` eine 64-Byte-Signatur ist:

```
OP_TOALTSTACK
OP_SIZE <64> OP_EQUALVERIFY
OP_DUP <x(G)> OP_CHECKSIGVERIFY
OP_SHA1
OP_FROMALTSTACK OP_IF OP_SHA1 OP_ENDIF
OP_SWAP
OP_DUP OP_DUP OP_0 OP_ADD OP_EQUALVERIFY
OP_SHA1 OP_EQUAL
```

Der Zahlen-Roundtrip validiert `a`, ohne seine ursprünglichen Bytes zu verlieren.
Die Signaturprüfung verwendet DEFAULT und bindet somit alle tatsächlichen
Outputs. Der übrige Ausdruck prüft genau eine der beiden Beziehungen

```
SHA1(sigma)       = SHA1(a), oder
SHA1(SHA1(sigma)) = SHA1(a).
```

Ein vorgelagerter arithmetischer Verifier müsste `a` zusätzlich an den
Referenz-Skalar binden. Das ist hier kein fertiger Verifier. Der Ausdruck
erzwingt auch nicht `R=G`; die folgende Schranke erlaubt dem ehrlichen Sucher
großzügig jede native 64-Byte-Signatur. Eine zusätzliche Nonce-Beschränkung
vergrößert den Kandidatenraum nicht.

Ressourcen dieses **rohen, nicht ausgeführten Grenzfall-Templates**:

| Größe | Grenze |
| --- | --- |
| Locking-Script | 53 Bytes, direkt serialisiert, kein Compilerlauf |
| Operanden bei Eintritt | 2: `a`, `sigma` |
| Zusätzliche Hint-Items pro Aufruf und insgesamt | 1: `path_bit` |
| Gesamte Datenitems bei Eintritt | 3; alle gleichzeitig vorhanden |
| Kombinierter Main-/Altstack-Peak | 5, aus dem vollständigen Layout abgeleitet |
| Vollständige Witness-Items bei 33-Byte-Controlblock | 5 einschließlich Leaf und Controlblock |
| Serialisierter Witness bei vierbyteigem `a` | 160 bzw. 161 Bytes für leeren bzw. einbyteigen Selektor |
| Signaturbudget bei erfolgreichem Aufruf | 50 Einheiten |

Kein Ressourcenwert stammt aus einem Interpreterlauf. Es wird keine
Konsens-/Policy-Klassifikation des Templates oder eines vollständigen Spends
behauptet. Der Peak umfasst den gespeicherten Selektor und die temporären
Werte des Zahlenchecks. Der Einzelaufruf liegt deutlich unter 1.000 Items;
eine unbekannte Verifier-Komposition ist damit nicht vermessen.

## 2. Die erste Verbindung zweier Hashgraphen

Die betrachtete Familie ist präzise eingeschränkt:

1. Native Wurzeln sind echte 64-Byte-Signaturen. Die Referenzseite erzeugt
   durch arithmetisch gebundene kurze Seeds und ausgewählte native Hashpfade
   rohe 20-/32-Byte-Tester. Sie besitzt noch keinen unabhängig an `s`
   gebundenen 64-Byte-Container. Insbesondere wird eine unverifizierte
   Witness-Kopie des ganzen Signaturwertes nicht bereits als gebunden angenommen.
2. Zwischen diesen Wurzeln werden Werte kopiert, ausgewählt, gehasht und auf
   vollständige Bytegleichheit geprüft. Die Hashprimitive sind SHA1,
   RIPEMD160 und SHA256. HASH160 wird als SHA256 gefolgt von RIPEMD160 gezählt,
   HASH256 als zwei SHA256-Aufrufe. Wiederholte Abfragen desselben Primitivs
   auf denselben Bytes sind dieselbe Orakelabfrage.
3. Die Bindung soll durch mindestens eine positive Gleichheitsverbindung
   zwischen einem nativen und einem unabhängig arithmetisch gebundenen Wert
   entstehen. Identische Kopien eines ungebundenen Witness-Wertes erfüllen
   diese Voraussetzung nicht. Zusätzliche CHECKSIG-Gruppenrelationen liegen
   außerhalb dieser Familie.
4. Die Hashprimitive werden als unabhängige ideale Funktionen mit ihrer
   jeweiligen Ausgabelänge modelliert. Der Sucher darf adaptiv arbeiten,
   Wurzeln verwerfen, Zwischenwerte speichern und den gesamten Suchzustand
   behalten. Alle Aufbau- und Suchabfragen zählen gemeinsam.

Betrachte die **erste** Verbindung eines nativen und eines Referenzpfads.
Direkt an den Wurzeln kann die Signatur nicht mit einem kurzen Seed oder
einem 20-/32-Byte-Tester identisch sein. Erzeugten beide Seiten den gleichen
Wert durch dasselbe Hashprimitiv auf bereits gleichen Eingaben, wären ihre
Eingabepfade schon vorher verbunden gewesen. Also muss die erste Verbindung
gleiche Hashausgaben aus zwei verschiedenen frischen Orakelabfragen benutzen.
Bei verschiedenen Hashprimitiven sind Ausgaben gleicher Länge ebenso ein
Kollisionstreffer im Modell. Das gilt auch dann, wenn die Endpfade später
viele strukturell identische Weiterhashungen teilen.

Bei insgesamt `q160` frischen 160-Bit-Ausgaben und `q256` frischen
256-Bit-Ausgaben folgt deshalb großzügig

```
Pr[eine solche Brücke]
  <= binomial(q160,2)/2^160 + binomial(q256,2)/2^256
  <= Q*(Q-1)/2^161,  Q=q160+q256.
```

Die Schranke zählt auch Kollisionen innerhalb nur einer Seite und ist deshalb
nicht scharf. Bei `Q=2^64` ist sie kleiner als `2^-33`. Für Erfolgschance 1/2
verlangt bereits diese großzügige Schranke ungefähr `2^80` Abfragen.
Ein zusätzlicher Faktor für die Herstellung gültiger Signaturen oder die
arithmetische Prüfung ist dabei vollständig geschenkt.

Der übliche einzelne 20/64-Kreuzvergleich hat die schärfere, bereits früher
notierte `Q^2/2^162`-Schranke bei optimal zwischen zwei Listen aufgeteiltem
Gesamtbudget. Die neue Aussage ist gerade, dass frei gewählte innere Pfade,
Mehrfachvergleiche und Struktur-Sharing in dieser Familie nicht ohne
entsprechende neue Abfragen unter die 160-Bit-Schnittstelle kommen.

**Lange vorab festgelegte Konstanten:** Werden `M` unabhängig festgelegte
160-Bit-Zielwerte zusätzlich bereitgestellt, kommt im allgemeinen Fall
`M*Q/2^160` hinzu. Wurden sie durch Hashabfragen konstruiert, gehören diese
Abfragen bereits zu `Q`; anderenfalls müssen Erstellung, Speicherung und
Prüfung der Ziele separat bezahlt werden. Ein nach Beobachtung des nativen
Wertes schlicht gleich gewählter Witness-Root ist kein unabhängiger
arithmetisch gebundener Zielwert. Diese Voraussetzung ist entscheidend.

## 3. Vollständig ausgezähltes adaptives Beispiel

Das Modell hat zwei getrennte Eingabewurzeln `A=4`, `B=5` und Hashausgaben
aus `{0,1,2,3}`. Alle `4^6=4096` Funktionen dieses gesamten kleinen Raums
werden aufgezählt. Die erste und zweite Abfrage sind `H(A)` und `H(B)`;
die dritte Eingabe ist **adaptiv** der bereits beobachtete Wert `H(A)`.
Wegen der getrennten Wurzel-/Ausgabemengen sind diese drei Eingaben immer
verschieden.

Der Sucher darf den Pfad mit einem oder zwei Schritten auswählen. Die
vollständige Auszählung ergibt:

| Ereignis | Günstige Funktionen | Exakte Wahrscheinlichkeit |
| --- | ---: | ---: |
| `H(A)=H(B)` | 1.024 | 1/4 |
| `H(H(A))=H(B)` | 1.024 | 1/4 |
| mindestens einer der zwei Pfade passt | 1.792 | 7/16 |
| beide Pfade passen | 256 | 1/16 |
| irgendeine Kollision der drei frischen Ausgaben | 2.560 | 5/8 |

Jede der 1.792 erfolgreichen adaptiven Pfadwahlen besitzt tatsächlich die
behauptete Kollision. Die Rechnung behandelt Hashketten somit nicht als
unabhängige Zufallsereignisse, sondern enumeriert eine einzige konsistente
Funktion einschließlich aller inneren Zyklen. Eine Pfadauswahl kann die
Erfolgschance erhöhen; sie beseitigt den vollen Ausgabe-Kollisionstreffer
nicht. Das Toy-Orakel mit zwei Bit ist ausdrücklich keine Bitcoin-Hashfunktion.

## 4. Warum eine kleine Checksumme noch kein ausführbarer Ausweg ist

Könnte Script tatsächlich `truncate_l(SHA1(sigma))` liefern, hätte ein
Kreuzvergleich nur `l` Bit statt 160. Diese Operation ist aber kein Hashpfad:
Die vorhandenen Hash-Opcodes liefern ganze 20- oder 32-Byte-Items, `SIZE`
meldet deren konstante Länge und die Zahlenoperationen können sie nicht als
vierbyteige ScriptNum lesen. Das gilt auch bei gemeinsamem Nonce-Präfix;
dieses Präfix wird durch die Signaturprüfung nicht als separates Stackitem
ausgegeben.

Eine Lookup-Tabelle kann ausgewählten vollständigen Hashwerten kleine
Checksummen zuordnen. Sie muss dabei zunächst den vollständigen Hashwert
treffen; ihre Größe oder die Arbeit zum Erzeugen ihrer Endpunkte verschwindet
nicht aus der Rechnung. Ein durch viele Hashwörter beschriebener großer Baum
ist ein kompaktes *Prüfprogramm*, keine kostenlos erzeugte Liste bereits
berechneter Endpunkte. Seine neu berechneten Zustände fallen unter `Q`.
Eine arithmetisch behauptete kurze Checksumme ohne diese native Auswertung
bleibt dagegen frei vom nativen Signaturwert wählbar.

Die verwendeten Byte-/Opcode-Grenzen und die 64-Byte-Schnorr-Prüfung stehen in
[Bitcoin Core 30.3, Commit 49faec4f87f5cd19c88db01a82e5c68b087c8227](https://github.com/bitcoin/bitcoin/blob/49faec4f87f5cd19c88db01a82e5c68b087c8227/src/script/interpreter.cpp)
und [BIP342, Commit 24e96e870fffaa257b465ce1f0370c14aac588e8](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0342.mediawiki).
Die Kollisions-/Arbeitsfolgen sind eigene Analyse, keine dort behaupteten
Unmöglichkeitssätze.

## Offene Ausnahme und nächster gezielter Bedarf

Eine neue **native Gruppenrelation** könnte die Datenfluss-Annahme brechen.
Ebenso könnte ein spezifischer kryptanalytischer Angriff auf echte,
berechenbar signierbare 64-Byte-Schnorr-Nachrichten außerhalb des Idealmodells
liegen. Dieses Ergebnis schließt beide Wege ausdrücklich nicht aus.

Ein zielführender Folgeversuch muss daher entweder eine solche Gruppenrelation
liefern, eine echte partielle Bytefunktion des nativen Signaturwerts ausführen,
oder eine neue nachgewiesene Relation zwischen kurzen Kontrollwerten und dem
64-Byte-Container angeben. Eine weitere unveränderte Kombination aus
Hashwortwahl und vollständiger `EQUAL`-Prüfung ist durch die vorliegende
begrenzte Rechnung bereits erfasst.

Reproduktion: `python3 research/covenant-2026-09-17/continuation/r6_scalar_bridge.py`.
Es wurden keine Rust-/Bibliotheksdateien, Primitivmetriken oder Feldtests geändert.
