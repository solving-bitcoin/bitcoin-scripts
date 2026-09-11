#!/usr/bin/env bash
set -euo pipefail

datadir=$(mktemp -d)
base_cli=(bitcoin-cli -regtest -datadir="$datadir")
cleanup() { "${base_cli[@]}" stop >/dev/null 2>&1 || true; }
trap cleanup EXIT

bitcoind -regtest -datadir="$datadir" -fallbackfee=0.0001 -daemonwait >/dev/null
"${base_cli[@]}" createwallet binohash >/dev/null
wallet_cli=(bitcoin-cli -regtest -datadir="$datadir" -rpcwallet=binohash)

json_field() {
    python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

# Test-only private key 1; its public key is fixed and not used for funds.
test_wif=$(python3 - <<'PY'
import hashlib

alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
secret = (1).to_bytes(32, "big")
payload = bytes([239]) + secret + bytes([1])
value = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
number = int.from_bytes(value, "big")
encoded = ""
while number:
    number, remainder = divmod(number, 58)
    encoded = alphabet[remainder] + encoded
print(alphabet[0] * (len(value) - len(value.lstrip(bytes([0])))) + encoded)
PY
)
test_pubkey=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

funding_address=$("${wallet_cli[@]}" getnewaddress)
"${base_cli[@]}" generatetoaddress 101 "$funding_address" >/dev/null
multisig=$("${base_cli[@]}" createmultisig 1 "[\"$test_pubkey\"]")
p2sh_address=$(printf %s "$multisig" | json_field address)
redeem_script=$(printf %s "$multisig" | json_field redeemScript)
fund_txid=$("${wallet_cli[@]}" sendtoaddress "$p2sh_address" 1)
"${base_cli[@]}" generatetoaddress 1 "$funding_address" >/dev/null

fund_raw=$("${wallet_cli[@]}" gettransaction "$fund_txid" | json_field hex)
decoded=$("${base_cli[@]}" decoderawtransaction "$fund_raw")
utxo=$(printf %s "$decoded" | python3 -c '
import json, sys
tx = json.load(sys.stdin)
address = sys.argv[1]
output = next(o for o in tx["vout"] if o["scriptPubKey"].get("address") == address)
print(tx["txid"], output["n"], output["scriptPubKey"]["hex"], output["value"])
' "$p2sh_address")
read -r spend_txid spend_vout prev_script prev_amount <<<"$utxo"

raw=$("${base_cli[@]}" createrawtransaction \
    "[{\"txid\":\"$spend_txid\",\"vout\":$spend_vout}]" \
    "{\"$funding_address\":0.999}")
prevtx=$(printf '[{"txid":"%s","vout":%s,"scriptPubKey":"%s","redeemScript":"%s","amount":%s}]' \
    "$spend_txid" "$spend_vout" "$prev_script" "$redeem_script" "$prev_amount")
signed=$("${base_cli[@]}" signrawtransactionwithkey "$raw" "[\"$test_wif\"]" "$prevtx")
signed_hex=$(printf %s "$signed" | json_field hex)
complete=$(printf %s "$signed" | json_field complete)
"${base_cli[@]}" sendrawtransaction "$signed_hex" >/dev/null

printf 'core_version=%s\n' "$(bitcoind -version | head -1)"
printf 'p2sh_redeem_script_bytes=%s\n' "$(( ${#redeem_script} / 2 ))"
printf 'signed_transaction_complete=%s\n' "$complete"
printf 'legacy_p2sh_spend_accepted=true\n'
