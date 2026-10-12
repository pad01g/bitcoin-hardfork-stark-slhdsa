#!/usr/bin/env bash
# End-to-end test: 3-node regtest, SLH-DSA spending, legacy migration proofs
# for every supported template, partition + reorg, restart/replay.
# Requires `make bins` (release binaries in ./bin). PROVE_MODE=dev|real.
set -euo pipefail
cd "$(dirname "$0")/.."

PROVE_MODE="${PROVE_MODE:-dev}"
export PROVE_MODE
E2E=.e2e
RPC1=http://127.0.0.1:18443
RPC2=http://127.0.0.1:18444
RPC3=http://127.0.0.1:18445
# The CLI runs inside the compose network, so it addresses nodes by service name.
CRPC1=http://node1:18443
CRPC2=http://node2:18443
# E2E_MATURITY=1 keeps a real-proof run (PROVE_MODE=real) to 7 blocks.
MATURITY="${E2E_MATURITY:-10}"

log() { printf '\n\033[1;34m== %s\033[0m\n' "$*"; }
PASSED=0
cleanup() { if [ "$PASSED" != 1 ]; then docker compose logs --tail=40 || true; fi; docker compose down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT
die() { printf '\033[1;31mFAIL: %s\033[0m\n' "$*"; exit 1; }
rpc() { # rpc URL method [json params]
  local url=$1 method=$2 params=${3:-[]}
  curl -sS --max-time 43200 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$method\",\"params\":$params}" "$url"
}
rpcr() { local out; out=$(rpc "$@"); if [ "$(echo "$out" | jq -r '.error')" != "null" ]; then echo "rpc error: $(echo "$out" | jq -c .error)" >&2; return 1; fi; echo "$out" | jq -r '.result'; }
cli() { docker compose run --rm -T cli --rpc "$1" "${@:2}"; }
wait_rpc() { for i in $(seq 1 120); do if rpc "$1" getblockcount 2>/dev/null | grep -q result; then return 0; fi; sleep 1; done; die "rpc $1 not up"; }
wait_height() { # url height
  for i in $(seq 1 300); do h=$(rpcr "$1" getblockcount 2>/dev/null || echo -1); if [ "$h" -ge "$2" ]; then return 0; fi; sleep 1; done
  die "$1 did not reach height $2 (at $h)"
}
assert_eq() { if [ "$1" != "$2" ]; then die "$3: expected '$2' got '$1'"; fi; }
gen() { # gen URL count address: one block per call (a real proof can take hours)
  local i; for i in $(seq 1 "$2"); do rpcr "$1" generate "[1, \"$3\"]" | jq -c .; done
}

log "cleanup"
docker compose down -v >/dev/null 2>&1 || true
rm -rf "$E2E"; mkdir -p "$E2E/net" "$E2E/wallet" "$E2E/node1" "$E2E/node2" "$E2E/node3"
docker compose build -q node1

# Deterministic legacy secp256k1 secrets (test only).
K1=$(printf '11%.0s' $(seq 1 32)); K2=$(printf '22%.0s' $(seq 1 32)); K3=$(printf '33%.0s' $(seq 1 32))
TX_P2WPKH=$(printf 'a1%.0s' $(seq 1 32)); TX_P2PKH=$(printf 'a2%.0s' $(seq 1 32)); TX_P2TR=$(printf 'a3%.0s' $(seq 1 32))
TX_P2SH=$(printf 'a4%.0s' $(seq 1 32)); TX_P2PK=$(printf 'a5%.0s' $(seq 1 32)); TX_WSH=$(printf 'a6%.0s' $(seq 1 32)); TX_SHMS=$(printf 'a7%.0s' $(seq 1 32))

log "legacy scripts"
LS() { docker compose run --rm -T cli legacy-script "$@"; }
S_P2WPKH=$(LS --kind p2wpkh --legacy-key "$K1")
S_P2PKH=$(LS --kind p2pkh-uncompressed --legacy-key "$K2")
S_P2TR=$(LS --kind p2tr --legacy-key "$K3")
S_P2SH=$(LS --kind p2sh-p2wpkh --legacy-key "$K1")
S_P2PK=$(LS --kind p2pk --legacy-key "$K2")
S_WSH=$(LS --kind p2wsh-multisig --threshold 2 --legacy-key "$K1" --legacy-key "$K2" --legacy-key "$K3")
S_SHMS=$(LS --kind p2sh-multisig --threshold 1 --legacy-key "$K2" --legacy-key "$K3")
echo "p2wpkh=$S_P2WPKH p2tr=$S_P2TR wsh=$S_WSH"

log "genesis state (synthetic snapshot with legacy coins)"
docker compose run --rm -T tools synthetic --out-dir /net --name bhrt \
  --coin "$TX_P2WPKH:0:100000000:$S_P2WPKH" --coin "$TX_P2PKH:1:200000000:$S_P2PKH" \
  --coin "$TX_P2TR:0:300000000:$S_P2TR" --coin "$TX_P2SH:2:400000000:$S_P2SH" \
  --coin "$TX_P2PK:0:500000000:$S_P2PK" --coin "$TX_WSH:7:600000000:$S_WSH" --coin "$TX_SHMS:0:700000000:$S_SHMS"
# Shorten coinbase maturity for the test network (consensus param => new params hash).
jq ".coinbase_maturity = $MATURITY" "$E2E/net/params.json" > "$E2E/net/p.tmp" && mv "$E2E/net/p.tmp" "$E2E/net/params.json"
cat "$E2E/net/params.json"

log "start nodes (PROVE_MODE=$PROVE_MODE)"
docker compose up -d node1 node2 node3
wait_rpc $RPC1; wait_rpc $RPC2; wait_rpc $RPC3
G1=$(rpcr $RPC1 getblockchaininfo | jq -r .genesis_hash); G3=$(rpcr $RPC3 getblockchaininfo | jq -r .genesis_hash)
assert_eq "$G1" "$G3" "genesis hash"
assert_eq "$(rpcr $RPC1 getblockchaininfo | jq -r .utxos)" "7" "genesis utxo count"
# PAR-5: the guest image IDs in params.json are the ones every node runs.
BID=$(jq -r .block_image_id "$E2E/net/params.json"); MID=$(jq -r .migrate_image_id "$E2E/net/params.json")
for u in $RPC1 $RPC2 $RPC3; do
  assert_eq "$(rpcr $u getblockchaininfo | jq -r .block_image_id)" "$BID" "block image id on $u"
  assert_eq "$(rpcr $u getblockchaininfo | jq -r .migrate_image_id)" "$MID" "migrate image id on $u"
done
assert_eq "$(rpcr $RPC1 getblockchaininfo | jq -r .params_hash)" "$(rpcr $RPC3 getblockchaininfo | jq -r .params_hash)" "params hash"

log "wallets"
cli $CRPC1 keygen --out /wallet/alice.json --seed alice >/dev/null
cli $CRPC1 keygen --out /wallet/bob.json --seed bob >/dev/null
ALICE=$(cli $CRPC1 address --key /wallet/alice.json); BOB=$(cli $CRPC1 address --key /wallet/bob.json)
echo "alice=$ALICE bob=$BOB"

log "mine $((MATURITY+1)) blocks on node1 (each with a block proof)"
gen $RPC1 $((MATURITY+1)) "$ALICE"
wait_height $RPC3 $((MATURITY+1))
assert_eq "$(rpcr $RPC3 getbestblockhash)" "$(rpcr $RPC1 getbestblockhash)" "node3 synced tip"
assert_eq "$(rpcr $RPC2 getblockchaininfo | jq -r .state_root)" "$(rpcr $RPC1 getblockchaininfo | jq -r .state_root)" "state root"
B1=$(rpcr $RPC1 getblock "[\"$(rpcr $RPC1 getblockhash '[1]')\"]")
echo "$B1" | jq -c '{height, receipt_kind, receipt_bytes, witness_proofs}'
if [ "$PROVE_MODE" = real ]; then assert_eq "$(echo "$B1" | jq -r .receipt_kind)" "succinct" "real receipt"; else assert_eq "$(echo "$B1" | jq -r .receipt_kind)" "fake" "dev receipt"; fi
assert_eq "$(cli $CRPC1 balance --address "$ALICE")" "10000000000" "alice spendable balance (coinbases 1 and 2 mature at tip $((MATURITY+1)))"

log "SLH-DSA spend alice -> bob via node1, mined on node1, observed on node3"
TXID=$(cli $CRPC1 send --key /wallet/alice.json --to "$BOB" --amount 1234567 --fee 1000)
echo "txid=$TXID"
assert_eq "$(rpcr $RPC1 getrawmempool | jq -r length)" "1" "mempool size"
gen $RPC1 1 "$ALICE" >/dev/null
wait_height $RPC3 $((MATURITY+2))
assert_eq "$(rpcr $RPC3 getbalance "[\"$BOB\"]")" "1234567" "bob balance on node3"
assert_eq "$(rpcr $RPC3 getrawtransaction "[\"$TXID\"]" | jq -r .height)" "$((MATURITY+2))" "tx confirmed height"

log "invalid transaction is rejected (bad signature => SIG-2)"
set +e; ERR=$(cli $CRPC1 send --key /wallet/alice.json --to "$BOB" --amount 1 --fee 1 --corrupt-signature 2>&1); RC=$?; set -e
[ $RC -ne 0 ] || die "corrupted tx was accepted"
echo "rejected with: $(echo "$ERR" | tail -1)"
case "$ERR" in *SIG-2*) ;; *) die "bad tx not rejected with SIG-2: $ERR";; esac

log "forged receipt (right journal, wrong image id) is rejected by the node"
set +e; OUT=$(cli $CRPC2 migrate --prove-mode "$PROVE_MODE" --to "$BOB" --kind p2wpkh --legacy-key "$K1" --txid "$TX_P2WPKH" --vout 0 --forge-receipt 2>&1); RC=$?; set -e
[ $RC -ne 0 ] || die "forged migration receipt was accepted"
# A node that mines real proofs turns fake receipts away before MIG-2 is reached.
if [ "$PROVE_MODE" = real ]; then WANT="dev-mode (fake) migration receipts"; else WANT="MIG-2"; fi
case "$OUT" in *"$WANT"*) ;; *) die "forged receipt not rejected with '$WANT': $OUT";; esac
echo "rejected with: $(echo "$OUT" | tail -1)"

log "legacy migrations (zkVM-proven secp256k1 authorizations), submitted via node2"
MIG() { cli $CRPC2 migrate --prove-mode "$PROVE_MODE" --segment-po2 "${SEGMENT_PO2:-17}" --to "$BOB" "$@"; }
M1=$(MIG --kind p2wpkh --legacy-key "$K1" --txid "$TX_P2WPKH" --vout 0)
M2=$(MIG --kind p2pkh-uncompressed --legacy-key "$K2" --txid "$TX_P2PKH" --vout 1)
M3=$(MIG --kind p2tr --legacy-key "$K3" --txid "$TX_P2TR" --vout 0)
M4=$(MIG --kind p2sh-p2wpkh --legacy-key "$K1" --txid "$TX_P2SH" --vout 2)
M5=$(MIG --kind p2pk --legacy-key "$K2" --txid "$TX_P2PK" --vout 0)
M6=$(MIG --kind p2wsh-multisig --threshold 2 --legacy-key "$K1" --legacy-key "$K2" --legacy-key "$K3" --signer "$K1" --signer "$K3" --txid "$TX_WSH" --vout 7)
M7=$(MIG --kind p2sh-multisig --threshold 1 --legacy-key "$K2" --legacy-key "$K3" --signer "$K3" --txid "$TX_SHMS" --vout 0)
echo "migrations: $M1 $M2 $M3 $M4 $M5 $M6 $M7"
for i in $(seq 1 60); do n=$(rpcr $RPC1 getrawmempool | jq -r length); [ "$n" = 7 ] && break; sleep 1; done
assert_eq "$n" "7" "migration txs relayed node2 -> node1"

log "wrong key cannot migrate (guest rejects before a proof exists)"
set +e; OUT=$(cli $CRPC2 migrate --prove-mode "$PROVE_MODE" --to "$BOB" --kind p2wpkh --legacy-key "$K2" --txid "$TX_P2WPKH" --vout 0 2>&1); RC=$?; set -e
[ $RC -ne 0 ] || die "migration with wrong key succeeded"
echo "rejected: $(echo "$OUT" | tail -1)"

gen $RPC1 1 "$ALICE" >/dev/null
wait_height $RPC3 $((MATURITY+3))
LAST=$(rpcr $RPC3 getblock "[\"$(rpcr $RPC3 getbestblockhash)\"]")
assert_eq "$(echo "$LAST" | jq -r '.tx | length')" "8" "block holds 7 migrations"
assert_eq "$(rpcr $RPC3 listlegacy | jq -r length)" "0" "all legacy coins migrated"
EXPECTED=$((1234567 + 100000000 + 200000000 + 300000000 + 400000000 + 500000000 + 600000000 + 700000000 - 7*1000))
assert_eq "$(rpcr $RPC3 getbalance "[\"$BOB\"]")" "$EXPECTED" "bob balance after migrations"
assert_eq "$(rpcr $RPC1 getblockchaininfo | jq -r .state_root)" "$(rpcr $RPC3 getblockchaininfo | jq -r .state_root)" "state roots agree"

log "partition: stop node2, mine 1 on node1 and 2 on node3, reconnect => reorg to node3's chain"
H=$(rpcr $RPC1 getblockcount)
docker compose stop node2 >/dev/null
gen $RPC1 1 "$ALICE" >/dev/null
gen $RPC3 2 "$BOB" >/dev/null
TIP3=$(rpcr $RPC3 getbestblockhash)
docker compose start node2 >/dev/null
wait_rpc $RPC2
wait_height $RPC2 $((H+2)); wait_height $RPC1 $((H+2))
assert_eq "$(rpcr $RPC1 getbestblockhash)" "$TIP3" "node1 reorganized to node3 tip"
assert_eq "$(rpcr $RPC2 getbestblockhash)" "$TIP3" "node2 synced to node3 tip"
assert_eq "$(rpcr $RPC1 getblockchaininfo | jq -r .state_root)" "$(rpcr $RPC3 getblockchaininfo | jq -r .state_root)" "state roots after reorg"

log "restart node1: replay from disk with full validation"
docker compose restart node1 >/dev/null
wait_rpc $RPC1
assert_eq "$(rpcr $RPC1 getbestblockhash)" "$TIP3" "node1 tip after restart"
assert_eq "$(rpcr $RPC1 getblockchaininfo | jq -r .utxos)" "$(rpcr $RPC3 getblockchaininfo | jq -r .utxos)" "utxo count after restart"

log "ALL E2E CHECKS PASSED (prove_mode=$PROVE_MODE, height=$(rpcr $RPC1 getblockcount))"
PASSED=1
