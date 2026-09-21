# Pointlock: verbindlicher Forschungsbrief

Stand: 2026-09-18. Frage: Welche algebraischen Freiheiten können eine erst nach
Setup frei wählbare, signierte **256-Byte-Nachricht** im Pointlock/BitVM-Sinn
unter **100.000 vB insgesamt** publizieren? Dieses Dokument prüft vorhandene
Quellen; es behauptet keine neue Lösung und enthält keine neuen Laufmessungen.

## Zweck und Weitergabe

Ein Pointlock ist konzeptionell ein Hashlock mit algebraischer Struktur:
`H(x)` verlangt ein passendes Preimage; `T=tG` verlangt einen akzeptierten Spend,
aus dessen öffentlichem Transkript jeder effizient `t` extrahieren kann.
`t` muss nicht wörtlich im Witness stehen. Wissen um `t` oder eine gewöhnliche
gültige Signatur allein erfüllen diese Anforderung nicht.

**Das Offenlegen des gewählten Secrets beim Spend ist Absicht und eine
Korrektheitseigenschaft.** Davon strikt getrennt sind unbeabsichtigte Offenlegung
vor dem Spend und Offenlegung ungewählter Alternativlabels. Gerade für garbled
input labels darf die gewählte Öffnung nicht die Alternativen verfügbar machen.
Öffentliche Punktbeziehungen können algebraisch und ohne Setup-ZKP geprüft
werden; das beweist für sich allein weder Extraktion noch Label-Geheimhaltung.

Jede Delegation muss diesen vollständigen Mechanismus, die Zielbedingungen und
diese Klarstellung mitgeben und ihre rekursive Weitergabe an **alle** weiteren
Subagents verlangen. Für diesen Brief wurden keine Subagents eingesetzt.

## Bewiesene Baseline: Sum-Key

Auf secp256k1 seien `P,Q` gültige verschiedene Punkte, `T=P+Q != infinity`,
Skalararithmetik modulo Gruppenordnung `n`. Dass die Summe dem beabsichtigten
Target entspricht, ist vor Funding öffentlich zu prüfen. Das Script verlangt
dieselbe DER-Signatur samt Sighash-Byte bei demselben **tatsächlichen** Digest `z`:

```text
OP_SIZE 57 OP_GREATERTHAN OP_VERIFY
OP_DUP <P> OP_CHECKSIGVERIFY
<Q> OP_CHECKSIG
```

Für die ECDSA-Recovery-Punkte gilt
`R_P=(zG+rP)/s`, `R_Q=(zG+rQ)/s`. Eine mögliche x-Koordinate `r+n<p`
erzwingt ein kleines `r`; die gesamte strikte DER-Signatur samt Flag ist dann
höchstens `7+17+33=57` Bytes lang. Der Guard schließt diese Mehrdeutigkeit aus.
Beide Recovery-Punkte haben daher x-Koordinate `r`. Gleichheit würde `P=Q`
erzwingen, also sind sie entgegengesetzt. Folglich:

```text
2zG + rT = infinity
t = -2z/r mod n; anschließend tG=T prüfen.
```

Dies gilt für **jeden akzeptierten gemeinsamen Digest**, nicht nur eine
bestimmte Nonce oder den SINGLE-Bug. Bei `z=0` ist ein endliches nichtnulliges
Target unmöglich. Die Baseline hat keine CODESEPARATORs und keine Datenpushes
in Größe einer akzeptierten Signatur; Legacy FindAndDelete ändert deshalb den
scriptCode nicht. Bei Pools/Erweiterungen muss diese Eigenschaft neu geprüft
werden: dasselbe Sighash-Byte allein garantiert keinen gemeinsamen Digest.

Honest Common-G-Setup verwendet den Legacy-SINGLE-Bug-Digest, dessen Bytes
`01` gefolgt von 31 Nullbytes als ECDSA-Skalar **C=2^248, nicht 1** ergeben:

```text
Q=G; geheimer frischer Nonce k
r=x(kG) mod n; s=(C+r)/k; t=-2C/r; T=tG; P=T-G
```

Low-S normalisieren und Flag `0x03` anhängen; degenerierte Fälle und Signaturen
mit höchstens 57 Bytes verwerfen. Signatur, Nonce und `t` bleiben bis zur
beabsichtigten Veröffentlichung geheim. Dieses Setup **generiert T**; es öffnet
kein beliebig vorgegebenes T mit Common G. P2WSH trägt die Extraktionsgleichung,
aber nicht den konstanten Legacy-Digest. Ein Wrapper-Wechsel löst deshalb die
native Funding/Sighash-Abhängigkeit nicht. Tapscript führt dieses ECDSA-Script
nicht mit derselben Semantik aus.

## Tatsächliche Freiheiten und ihre Grenzen

- **Targetgenerierung:** frische geheime Nonces wählen, Common G wiederverwenden,
  unabhängige Targets zu festen Teilmengen-Codes kombinieren. Alle `P_i` müssen
  verschieden und ungleich `±G` sein; `k` und `-k` erzeugen dasselbe Target.
  Öffentliche affine Beziehungen zwischen Labelskalaren können nach einer
  Öffnung Alternativen verraten. Starke Nonce-Grinds brauchen eine eigene
  Analyse der erzeugten Verteilung.
- **Vorgegebenes Target mit bekanntem t:** kleine öffentliche Nichtnull-Multiplikatoren
  `a=1,2,...` prüfen, bis `r=-2C/(a*t)` als x-Koordinate zu `R` liftet;
  geheimen Nichtnull-Skalar `s` wählen und `P=(sR-CG)/r`, `Q=(-sR-CG)/r`
  bilden. Öffentlich `P+Q=aT` und die Schlüsselbedingungen prüfen. Extraktion
  liefert `t=-2z/(a*r)`. Hier braucht man `log_G(R)` nicht. Die erwartete
  Lift-Suche ist keine Worst-Case-Garantie; eine beliebige geheimnisabhängige
  Wahl von `a` könnte `t` offenlegen. Zwei kandidatenspezifische Schlüssel
  verlieren die Common-G-Tabellenersparnis.
- **Codierung und Verpackung:** Poolgrößen, feste Auswahlkardinalität,
  Tabellenrepräsentation und Transaktionsaufteilung dürfen geändert werden.
  Erforderlich bleiben mindestens `2^2048` nach Setup wählbare Nachrichten,
  eindeutige Decodierung und Bindung gegen Entfernen/Ersetzen von Offenlegungen.
  Common G verhindert das bekannte Cross-Pair-Problem unabhängiger P/Q-Listen;
  es repariert diese unabhängigen Listen nicht allgemein.
- **Andere Primitive:** SegWit-Rabatt, implizite Kandidatenmengen und neue
  algebraische Prädikate sind Forschungsfreiheiten. Sie erben den Sum-Key-Beweis
  nicht automatisch. Normale Signatur plus OP_RETURN, Schlüsselvernichtung,
  vor Funding festgelegte Nachricht und 128-Byte-Nutzlast ersetzen das Ziel nicht.

## Unfertige Spur: Anchor und getrennte Short-Checks

Ein öffentliches `tau=(r=x(T),s=1,ALL)` mit genau 40 Bytes authentifiziert
optional über HASH160 die Labelwahl. Setup muss die DER-Form und `r>p-n`
prüfen. Ein Check unter dem Witness-Schlüssel P beim tatsächlichen Anchor-Digest
`z0` bindet `P=(±T-z0G)/r`. Danach erfolgen `d` exakt 60 Byte lange Signaturen
unter **demselben P**, jeweils nach eigenem ausgeführten CODESEPARATOR.
Honest Generation leitet den P-Skalar aus `t,z0` ab und nutzt den bekannten
Nonce `±G/2`; alternative Standardflags können die exakte Länge ermöglichen.

Kennt der Extraktor den verwendeten Nonce-Skalar `k`, folgt für eine Short-Signatur
`p=(s*k-z)/r_short`, danach `t=±(r_anchor*p+z0)` mit Punktprüfung.
Auch wiederholtes `r_short` bei verschiedenen reduzierten Digests erlaubt
Nonce-Reuse-Extraktion unter Berücksichtigung beider Nonce-Vorzeichen.
**Ein bekanntes r allein ist kein bekannter Nonce-Skalar.** Exakt 60 Bytes
schließen `r+n` aus, erzwingen aber weder G/2 noch Nonce-Wiederverwendung.
Verschiedene Script-Suffixe garantieren auch keine verschiedenen Hashwerte.

Die entscheidende Lücke sind gültige Transkripte mit ausschließlich verschiedenen
unbekannten Nonces. Es gibt bisher weder allgemeinen Extraktionsbeweis noch
belastbare Angriffsuntergrenze gegen böswilliges Setup, adaptive Transaktionen
und alle zugelassenen Sighash-Modi. Mehr Checks allein schließen die Lücke nicht.

Die Platzhalter-Serialisierung ergibt `d=4: 83.880 vB`, `d=5: 93.085 vB`;
dies sind keine finanzierten gültigen Transaktionen und keine Setupbenchmarks.
Beim d=5-Profil: 115 separate Inputs, je 4 Hints und 32 Entry-Datenitems,
zusammen 460 Hints und 3.680 Entry-Datenitems; je ein zusätzliches Scriptitem.
Die je Input berechnete kombinierte Stack-Obergrenze 88 ist nicht Core-gemessen.
Evidenz der Serialisierung: `locally-reproduced`; Deployment: `unclassified`.

Die Native-Probe scheitert laut Forschungsnotiz am ersten Short-Check.
Vermutet wird, dass Interpreter `702544c` den ausgeführten CODESEPARATOR in
den BIP143-scriptCode einschließt statt danach zu beginnen. Dies ist noch kein
Core-Differentialbefund; `anchored-native-local.json` ist aktuell 0 Bytes lang.
Selbst eine Reparatur der ehrlichen Ausführung würde die Extraktionslücke
nicht schließen.

## Messlatte und bestehende Evidenz

Akzeptanz verlangt weniger als 100.000 gesamte vB für Erzeugung und Verbrauch
aller Publikationsoutputs einschließlich erstem P2TR-Hilfsoutput, vollständiger
Signaturen, Framing, Witness-/scriptSig-Serialisierung und Transaktionsrundung.
Der bestehende anfängliche Funding-UTXO ist die dokumentierte Ausgangsgrenze.
Setup soll auf einem **Standard-MacBook** idealerweise unter 100 ms liegen;
1–2 Sekunden sind schlecht, aber noch einigermaßen akzeptabel. Offchain-Speicher
ist egal; Tabellenerzeugung und notwendige Verifikation zählen zeitlich mit.
Rein algebraisches nichtinteraktives Setup, kein Setup-ZKP, keine praktische
Lösung durch `2^50`- oder `2^63`-Suche.

Die Core-validierte Sum-Key-Publikation braucht **185.146 vB**
(`5.967+99.065+80.114`), 183 P2SH-Pools, 3.114 Kandidaten und 729 Offenlegungen.
Der Bericht dokumentiert `differentially-validated` / `policy-validated` für
die konkreten Transaktionen; die algebraische Verallgemeinerung ist `inspected`.
Core: 30.3, Commit `49faec4f87f5cd19c88db01a82e5c68b087c8227`.
HASH160-Tabellen haben bei böswilligem Setup eine generische Kollisionsbindung
von etwa `2^80`, nicht bloß eine Preimage-Annahme. Vollständige BitVM-Integration
ist damit nicht validiert.

Der explizite Legacy-Tabellenbound **111.573,86 Bytes** gilt nur für die
angegebene Familie (`21N+93T`); er ist kein allgemeiner Unmöglichkeitsbeweis.
Windowed-small-R mit 39.396 vB ist wegen geschätzter `2^63.138`
SHA256-Kompressionen verworfen und besitzt zusätzlich keine allgemeine
Extraktionsgarantie. Die 92.706-vB-Variante publiziert nur 128 Bytes.

Neue Resultate müssen Sicherheitsannahmen, Extraktion, Konsens, Policy,
Byte-Messung und Setupzeit getrennt ausweisen. Erforderlich sind echte
post-Setup Nachrichtenauswahl, tatsächliche Digests, native finanzierte
Transaktionen und unabhängige Extraktion; Hardware, Build, Stichproben,
Streuung, deterministische Seeds, sämtliche Hints pro Aufruf/Batch und die
kombinierten Stack-Peaks sind zu dokumentieren. Policy-kompilierte finale
Scripts sind für Ausführung und Kosten identisch zu verwenden. Der gemeinsame
Tapscript-Helper beziehungsweise abgeschaltete Stack-Limits liefern keine
Konsensvalidierung. Für diesen Brief wurden keine Tests gestartet.

## Tatsächlich gelesene Repository-Quellen

- [AGENTS.md](../../AGENTS.md), [Index](../../knowledge/index.md),
  [Script-Referenz](../../knowledge/bitcoin-script-reference.md),
  [Kostenmodell](../../knowledge/cost-model.md); Katalogabfrage
  `python3 tools/kb.py search pointlock`.
- [Sum-Key README](../../src/signatures/pointlocks/sum_key/README.md),
  [Implementierung](../../src/signatures/pointlocks/sum_key/mod.rs),
  [Algebra/Setup](sum-pointlock.md), [Core-Vektorenbericht](sum_key_core_check.json),
  [Publikationsbericht](publication_core_check.json).
- [Anchor-Notiz](anchored-codesep.md),
  [Sizing-Code](../../examples/pointlock_anchored_codesep_size_probe.rs),
  [Native-Probe](../../examples/pointlock_anchored_native_probe.rs).
- [Familienbound](../../knowledge/negative-results/explicit-point-table-size-floor.md),
  [Windowed-Ablehnung](../../knowledge/negative-results/windowed-pointlock-setup-cost.md),
  [128-Byte-Abgrenzung](conditional-proof-compression.md).

Die verlinkten Berichte wurden gelesen, nicht neu ausgeführt. Die Quellnotiz
pinnt Compiler `124b561ed75ac3ec4c6ad99207d8dcdd3bc67180` und Interpreter
`702544c9a045ac4fc14846da6da6559e2b7cd9d1` für ihre historischen Ergebnisse.
Primärverweise aus dem README: [libsecp256k1 v0.6.0](https://github.com/bitcoin-core/secp256k1/blob/v0.6.0/src/ecdsa_impl.h)
und [BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki);
diese externen Seiten wurden für diesen Brief nicht neu abgerufen.
