//! JSON-RPC 2.0 over HTTP (RPC-*). Methods mirror the Bitcoin Core names
//! where the semantics match.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Result};
use axum::{extract::State, routing::post, Json, Router};
use bhss_primitives::address;
use bhss_primitives::types::*;
use bhss_primitives::{Decode, Encode, Hash32};
use bhss_prover::ProverConfig;
use serde_json::{json, Value};

use crate::chain::ChainState;
use crate::miner;
use crate::p2p::{Message, Network};

#[derive(Clone)]
pub struct RpcContext {
    pub chain: Arc<Mutex<ChainState>>,
    pub net: Arc<Network>,
    pub prover: ProverConfig,
    /// Serialises `generate` calls so templates never race each other.
    pub mining: Arc<tokio::sync::Mutex<()>>,
}

pub fn router(ctx: RpcContext) -> Router {
    Router::new().route("/", post(handle)).with_state(ctx)
}

async fn handle(State(ctx): State<RpcContext>, Json(req): Json<Value>) -> Json<Value> {
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();
    let params = req.get("params").cloned().unwrap_or(Value::Array(vec![]));
    let params: Vec<Value> = match params {
        Value::Array(a) => a,
        Value::Null => vec![],
        other => vec![other],
    };
    let result = dispatch(ctx, &method, params).await;
    Json(match result {
        Ok(v) => json!({ "jsonrpc": "2.0", "id": id, "result": v }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -1, "message": format!("{e:#}") } }),
    })
}

fn hash_from(v: Option<&Value>) -> Result<Hash32> {
    let s = v.and_then(|v| v.as_str()).ok_or_else(|| anyhow!("expected hex hash"))?;
    hex::decode(s)?.try_into().map_err(|_| anyhow!("hash must be 32 bytes"))
}

fn u64_from(v: Option<&Value>) -> Result<u64> {
    v.and_then(|v| v.as_u64()).ok_or_else(|| anyhow!("expected integer"))
}

fn kind_json(k: &OutputKind) -> Value {
    match k {
        OutputKind::P2pkSlh { pkh } => json!({ "type": "p2pk_slh", "pkh": hex::encode(pkh) }),
        OutputKind::MultisigSlh { k, pkhs } => json!({ "type": "multisig_slh", "k": k, "pkhs": pkhs.iter().map(hex::encode).collect::<Vec<_>>() }),
        OutputKind::Timelock { abs_height, rel_blocks, inner } => json!({ "type": "timelock", "abs_height": abs_height, "rel_blocks": rel_blocks, "inner": kind_json(inner) }),
        OutputKind::Data { data } => json!({ "type": "data", "data": hex::encode(data) }),
        OutputKind::Legacy { script_pubkey } => json!({ "type": "legacy", "script_pubkey": hex::encode(script_pubkey) }),
    }
}

fn coin_json(hrp: &str, op: &OutPoint, c: &Coin) -> Value {
    json!({
        "txid": hex::encode(op.txid), "vout": op.vout, "value": c.output.value,
        "height": c.height, "coinbase": c.coinbase, "kind": kind_json(&c.output.kind),
        "address": address::encode(hrp, &c.output.kind).ok(),
    })
}

fn block_json(c: &ChainState, b: &Block) -> Value {
    let hash = b.hash();
    let height = c.heights.get(&hash).copied();
    let receipt_kind = if b.receipt.is_empty() {
        "none"
    } else if bhss_prover::decode_receipt(&b.receipt).map(|r| bhss_prover::is_fake(&r)).unwrap_or(true) {
        "fake"
    } else {
        "stark"
    };
    json!({
        "hash": hex::encode(hash), "height": height, "version": b.header.version,
        "previousblockhash": hex::encode(b.header.prev_hash), "merkleroot": hex::encode(b.header.merkle_root),
        "state_root": hex::encode(b.header.state_root), "time": b.header.time, "bits": format!("{:08x}", b.header.bits),
        "nonce": b.header.nonce, "tx": b.txs.iter().map(|t| hex::encode(t.txid())).collect::<Vec<_>>(),
        "size": b.committed_tx_bytes(), "receipt_bytes": b.receipt.len(), "receipt_kind": receipt_kind,
        "witness_coins": b.witness.coins.len(), "witness_proofs": b.witness.proofs.len(),
        "in_main_chain": height.map(|h| c.main.get(h as usize) == Some(&hash)).unwrap_or(false),
    })
}

fn tx_json(t: &Transaction) -> Value {
    json!({
        "txid": hex::encode(t.txid()), "version": t.version, "locktime": t.locktime,
        "inputs": t.inputs.iter().map(|i| json!({
            "txid": hex::encode(i.prevout.txid), "vout": i.prevout.vout,
            "witness": match &i.witness { Witness::Slh { signers } => json!({"type":"slh","signers": signers.len()}), Witness::Legacy => json!({"type":"legacy"}), Witness::Coinbase => json!({"type":"coinbase"}) },
        })).collect::<Vec<_>>(),
        "outputs": t.outputs.iter().map(|o| json!({ "value": o.value, "kind": kind_json(&o.kind) })).collect::<Vec<_>>(),
        "proofs": t.proofs.len(),
        "hex": hex::encode(t.to_bytes()),
    })
}

async fn dispatch(ctx: RpcContext, method: &str, p: Vec<Value>) -> Result<Value> {
    match method {
        "getblockchaininfo" => {
            let c = ctx.chain.lock().unwrap();
            Ok(json!({
                "chain": c.params.name, "blocks": c.height(), "bestblockhash": hex::encode(c.tip.hash),
                "state_root": hex::encode(c.tip.state_root), "genesis_hash": hex::encode(c.genesis_hash),
                "params_hash": hex::encode(c.params_hash), "utxos": c.state.coins.len(),
                "mempool": c.mempool.txs.len(), "peers": ctx.net.peers.lock().unwrap().len(),
                "block_image_id": hex::encode(bhss_prover::block_image_id()),
                "migrate_image_id": hex::encode(bhss_prover::migrate_image_id()),
                "require_real_proofs": c.params.require_real_proofs, "prove_mode": format!("{:?}", ctx.prover.mode).to_lowercase(),
            }))
        }
        "getblockcount" => Ok(json!(ctx.chain.lock().unwrap().height())),
        "getbestblockhash" => Ok(json!(hex::encode(ctx.chain.lock().unwrap().tip.hash))),
        "getblockhash" => {
            let h = u64_from(p.first())? as u32;
            let c = ctx.chain.lock().unwrap();
            Ok(json!(hex::encode(c.main.get(h as usize).ok_or_else(|| anyhow!("height out of range"))?)))
        }
        "getblock" => {
            let hash = hash_from(p.first())?;
            let c = ctx.chain.lock().unwrap();
            let b = c.blocks.get(&hash).ok_or_else(|| anyhow!("block not found"))?;
            Ok(block_json(&c, b))
        }
        "getrawblock" => {
            let hash = hash_from(p.first())?;
            let c = ctx.chain.lock().unwrap();
            let b = c.blocks.get(&hash).ok_or_else(|| anyhow!("block not found"))?;
            Ok(json!(hex::encode(b.to_bytes())))
        }
        "getrawtransaction" => {
            let txid = hash_from(p.first())?;
            let c = ctx.chain.lock().unwrap();
            if let Some(bh) = c.tx_index.get(&txid) {
                let b = &c.blocks[bh];
                let t = b.txs.iter().find(|t| t.txid() == txid).unwrap();
                let mut v = tx_json(t);
                v["blockhash"] = json!(hex::encode(bh));
                v["height"] = json!(c.heights.get(bh));
                return Ok(v);
            }
            if let Some((t, _)) = c.mempool.txs.iter().find(|(t, _)| t.txid() == txid) {
                return Ok(tx_json(t));
            }
            bail!("transaction not found")
        }
        "decoderawtransaction" => {
            let hexs = p.first().and_then(|v| v.as_str()).ok_or_else(|| anyhow!("expected hex"))?;
            let t = Transaction::from_bytes(&hex::decode(hexs)?).map_err(|e| anyhow!("decode: {e}"))?;
            Ok(tx_json(&t))
        }
        "sendrawtransaction" => {
            let hexs = p.first().and_then(|v| v.as_str()).ok_or_else(|| anyhow!("expected hex"))?;
            let t = Transaction::from_bytes(&hex::decode(hexs)?).map_err(|e| anyhow!("decode: {e}"))?;
            let txid = ctx.chain.lock().unwrap().add_to_mempool(t.clone())?;
            ctx.net.broadcast(Message::Tx(t));
            Ok(json!(hex::encode(txid)))
        }
        "getrawmempool" => {
            let c = ctx.chain.lock().unwrap();
            Ok(json!(c.mempool.txs.iter().map(|(t, _)| hex::encode(t.txid())).collect::<Vec<_>>()))
        }
        "listunspent" => {
            // params: [address | null, min_confirmations?]
            let c = ctx.chain.lock().unwrap();
            let kind = match p.first() {
                Some(Value::String(a)) => Some(address::decode(&c.params.name, a).map_err(|e| anyhow!("address: {e}"))?),
                _ => None,
            };
            let minconf = p.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let tip = c.height();
            let mut v: Vec<Value> = c
                .find_coins(kind.as_ref())
                .into_iter()
                .filter(|(_, coin)| tip + 1 - coin.height >= minconf)
                .map(|(op, coin)| coin_json(&c.params.name, &op, &coin))
                .collect();
            v.sort_by_key(|x| x["height"].as_u64());
            Ok(Value::Array(v))
        }
        "listlegacy" => {
            let c = ctx.chain.lock().unwrap();
            let script = p.first().and_then(|v| v.as_str()).map(hex::decode).transpose()?;
            let v: Vec<Value> = c
                .state
                .coins
                .iter()
                .filter(|(_, coin)| match (&coin.output.kind, &script) {
                    (OutputKind::Legacy { script_pubkey }, Some(s)) => script_pubkey == s,
                    (OutputKind::Legacy { .. }, None) => true,
                    _ => false,
                })
                .map(|(op, coin)| coin_json(&c.params.name, op, coin))
                .collect();
            Ok(Value::Array(v))
        }
        "getcoin" => {
            let txid = hash_from(p.first())?;
            let vout = u64_from(p.get(1))? as u32;
            let c = ctx.chain.lock().unwrap();
            let op = OutPoint::new(txid, vout);
            let coin = c.state.get(&op).ok_or_else(|| anyhow!("coin not found"))?;
            let proof = c.state.smt.prove(&op.smt_key());
            let mut v = coin_json(&c.params.name, &op, coin);
            v["coin_hex"] = json!(hex::encode(coin.to_bytes()));
            v["smt_proof_hex"] = json!(hex::encode(proof.to_bytes()));
            v["state_root"] = json!(hex::encode(c.tip.state_root));
            Ok(v)
        }
        "getbalance" => {
            let c = ctx.chain.lock().unwrap();
            let a = p.first().and_then(|v| v.as_str()).ok_or_else(|| anyhow!("expected address"))?;
            let kind = address::decode(&c.params.name, a).map_err(|e| anyhow!("address: {e}"))?;
            let minconf = p.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let tip = c.height();
            let sum: u64 = c.find_coins(Some(&kind)).iter().filter(|(_, coin)| tip + 1 - coin.height >= minconf).map(|(_, coin)| coin.output.value).sum();
            Ok(json!(sum))
        }
        "generate" => {
            let n = u64_from(p.first())?;
            let a = p.get(1).and_then(|v| v.as_str()).ok_or_else(|| anyhow!("expected address"))?.to_string();
            let _guard = ctx.mining.lock().await;
            let mut hashes = Vec::new();
            for _ in 0..n {
                let hash = generate_one(&ctx, &a).await?;
                hashes.push(hex::encode(hash));
            }
            Ok(json!(hashes))
        }
        "getpeerinfo" => {
            let peers = ctx.net.peers.lock().unwrap();
            Ok(json!(peers.iter().map(|(id, addr)| json!({ "id": id, "addr": addr.to_string() })).collect::<Vec<_>>()))
        }
        "getparams" => {
            let c = ctx.chain.lock().unwrap();
            Ok(serde_json::to_value(&c.params)?)
        }
        _ => bail!("unknown method {method}"),
    }
}

async fn generate_one(ctx: &RpcContext, address: &str) -> Result<Hash32> {
    let (template, payout) = {
        let c = ctx.chain.lock().unwrap();
        let payout = address::decode(&c.params.name, address).map_err(|e| anyhow!("address: {e}"))?;
        let height = c.height() + 1;
        let cb_size = miner::coinbase_tx(height, 0, payout.clone()).committed_size();
        let (txs, coins) = miner::select_txs(&c.params, cb_size, &c.mempool.txs);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as u32;
        (
            miner::Template { params: c.params.clone(), genesis_hash: c.genesis_hash, prev: c.tip.clone(), txs, coins, state: c.state.clone(), time: now },
            payout,
        )
    };
    let prover = ctx.prover.clone();
    let block = tokio::task::spawn_blocking(move || miner::seal_and_prove(template, payout, &prover)).await??;
    let hash = block.hash();
    {
        let mut c = ctx.chain.lock().unwrap();
        match c.accept_block(block.clone(), true)? {
            crate::chain::Accept::Connected => {}
            other => bail!("mined block not connected: {other:?} (tip moved?)"),
        }
    }
    tracing::info!(hash = hex::encode(hash), "mined block");
    ctx.net.broadcast(Message::Block(block));
    Ok(hash)
}
