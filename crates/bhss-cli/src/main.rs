//! bhss-cli — keys, addresses, spending and legacy migration.
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use bhss_legacy::{sign as lsign, MigrationAuth, MigrationInput};
use bhss_primitives::types::*;
use bhss_primitives::{address, Decode, Encode, Hash32};
use bhss_prover::{ProveMode, ProverConfig};
use bhss_slhdsa::SecretKey;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};

#[derive(Parser)]
#[command(name = "bhss-cli", about = "BHSS wallet and RPC client")]
struct Cli {
    #[arg(long, global = true, default_value = "http://127.0.0.1:18443")]
    rpc: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum, Debug)]
enum LegacyKindArg {
    P2pkh,
    P2pkhUncompressed,
    P2wpkh,
    P2shP2wpkh,
    P2pk,
    P2tr,
    P2wshMultisig,
    P2shMultisig,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate an SLH-DSA-SHA2-128s key file.
    Keygen {
        #[arg(long)]
        out: PathBuf,
        /// Deterministic key from a seed string (tests only).
        #[arg(long)]
        seed: Option<String>,
    },
    /// Print the P2PK-SLH address of a key file.
    Address {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        hrp: Option<String>,
    },
    /// Spendable balance (coinbase maturity applied) of an address.
    Balance {
        #[arg(long)]
        address: String,
    },
    /// Send `amount` satoshis from the key's address to `to`.
    Send {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 1000)]
        fee: u64,
        /// Test hook: flip a byte of the first signature so the node must reject (SIG-2).
        #[arg(long, hide = true)]
        corrupt_signature: bool,
    },
    /// Build a legacy scriptPubKey for a secp256k1 secret (hex, 32 bytes).
    LegacyScript {
        #[arg(long)]
        kind: LegacyKindArg,
        #[arg(long = "legacy-key")]
        keys: Vec<String>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
    },
    /// Migrate a legacy coin: prove the secp256k1 authorization in the zkVM
    /// and spend it into an SLH address.
    Migrate {
        #[arg(long)]
        kind: LegacyKindArg,
        #[arg(long = "legacy-key")]
        keys: Vec<String>,
        /// Signers for multisig (hex secrets), subset of --legacy-key in script order.
        #[arg(long = "signer")]
        signers: Vec<String>,
        #[arg(long, default_value_t = 1)]
        threshold: usize,
        #[arg(long)]
        txid: String,
        #[arg(long)]
        vout: u32,
        #[arg(long)]
        to: String,
        #[arg(long, default_value_t = 1000)]
        fee: u64,
        #[arg(long, default_value = "dev")]
        prove_mode: ProveMode,
        #[arg(long, default_value_t = 20)]
        segment_po2: u32,
    },
    /// Raw JSON-RPC call: `rpc <method> [param-json ...]`.
    Rpc {
        method: String,
        params: Vec<String>,
    },
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    secret: String,
    pubkey: String,
}

fn load_key(path: &PathBuf) -> Result<SecretKey> {
    let kf: KeyFile = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    SecretKey::from_bytes(&hex::decode(kf.secret)?).map_err(|_| anyhow!("bad secret key"))
}

struct Rpc {
    url: String,
    client: reqwest::blocking::Client,
}

impl Rpc {
    fn new(url: &str) -> Self {
        Self { url: url.to_string(), client: reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(7200)).build().unwrap() }
    }
    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let resp: Value = self
            .client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .with_context(|| format!("rpc {method}"))?
            .json()?;
        if let Some(err) = resp.get("error") {
            if !err.is_null() {
                bail!("rpc {method}: {}", err["message"].as_str().unwrap_or("error"));
            }
        }
        Ok(resp["result"].clone())
    }
    fn hrp(&self) -> Result<String> {
        Ok(self.call("getblockchaininfo", json!([]))?["chain"].as_str().unwrap_or("bhrt").to_string())
    }
    /// Spendable coins of `addr` at the next block height (coinbase maturity applied).
    fn spendable(&self, addr: &str) -> Result<Vec<Value>> {
        let info = self.call("getblockchaininfo", json!([]))?;
        let tip = info["blocks"].as_u64().unwrap_or(0);
        let maturity = self.call("getparams", json!([]))?["coinbase_maturity"].as_u64().unwrap_or(100);
        let utxos = self.call("listunspent", json!([addr, 0]))?;
        Ok(utxos
            .as_array()
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|u| !u["coinbase"].as_bool().unwrap_or(false) || tip + 1 >= u["height"].as_u64().unwrap_or(0) + maturity)
            .collect())
    }
    fn genesis_hash(&self) -> Result<Hash32> {
        let s = self.call("getblockchaininfo", json!([]))?["genesis_hash"].as_str().unwrap_or("").to_string();
        hex::decode(s)?.try_into().map_err(|_| anyhow!("genesis hash"))
    }
}

fn secret_hex(s: &str) -> Result<k256::SecretKey> {
    let b: [u8; 32] = hex::decode(s)?.try_into().map_err(|_| anyhow!("legacy key must be 32 bytes hex"))?;
    lsign::secret_from_bytes(&b).ok_or_else(|| anyhow!("invalid secp256k1 secret"))
}

fn legacy_script(kind: LegacyKindArg, keys: &[k256::SecretKey], threshold: usize) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let k0 = keys.first().ok_or_else(|| anyhow!("need at least one --legacy-key"))?;
    Ok(match kind {
        LegacyKindArg::P2pkh => (lsign::script_p2pkh(&lsign::compressed_pubkey(k0)), None),
        LegacyKindArg::P2pkhUncompressed => (lsign::script_p2pkh(&lsign::uncompressed_pubkey(k0)), None),
        LegacyKindArg::P2wpkh => (lsign::script_p2wpkh(&lsign::compressed_pubkey(k0)), None),
        LegacyKindArg::P2shP2wpkh => (lsign::script_p2sh_p2wpkh(&lsign::compressed_pubkey(k0)), None),
        LegacyKindArg::P2pk => (lsign::script_p2pk(&lsign::compressed_pubkey(k0)), None),
        LegacyKindArg::P2tr => (lsign::script_p2tr(&lsign::xonly_pubkey(&lsign::taproot_tweak(k0))), None),
        LegacyKindArg::P2wshMultisig | LegacyKindArg::P2shMultisig => {
            let pks: Vec<Vec<u8>> = keys.iter().map(lsign::compressed_pubkey).collect();
            let ms = lsign::script_multisig(threshold, &pks);
            let spk = if matches!(kind, LegacyKindArg::P2wshMultisig) { lsign::script_p2wsh_of(&ms) } else { lsign::script_p2sh_of(&ms) };
            (spk, Some(ms))
        }
    })
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_writer(std::io::stderr).init();
    let cli = Cli::parse();
    let rpc = Rpc::new(&cli.rpc);
    match cli.cmd {
        Cmd::Keygen { out, seed } => {
            let sk = match seed {
                Some(s) => {
                    let h = bhss_primitives::hash::sha256(s.as_bytes());
                    let h2 = bhss_primitives::hash::sha256(&h);
                    SecretKey::from_seeds(h[..16].try_into().unwrap(), h[16..].try_into().unwrap(), h2[..16].try_into().unwrap())
                }
                None => SecretKey::generate(&mut rand::rngs::OsRng),
            };
            let kf = KeyFile { secret: hex::encode(sk.to_bytes()), pubkey: hex::encode(sk.public_key().0) };
            std::fs::write(&out, serde_json::to_string_pretty(&kf)?)?;
            println!("{}", kf.pubkey);
        }
        Cmd::Address { key, hrp } => {
            let sk = load_key(&key)?;
            let hrp = match hrp {
                Some(h) => h,
                None => rpc.hrp()?,
            };
            println!("{}", address::encode(&hrp, &OutputKind::P2pkSlh { pkh: sk.public_key().hash() })?);
        }
        Cmd::Balance { address } => {
            let sum: u64 = rpc.spendable(&address)?.iter().map(|u| u["value"].as_u64().unwrap_or(0)).sum();
            println!("{sum}");
        }
        Cmd::Send { key, to, amount, fee, corrupt_signature } => {
            let sk = load_key(&key)?;
            let hrp = rpc.hrp()?;
            let genesis = rpc.genesis_hash()?;
            let my_kind = OutputKind::P2pkSlh { pkh: sk.public_key().hash() };
            let my_addr = address::encode(&hrp, &my_kind)?;
            let to_kind = address::decode(&hrp, &to).map_err(|e| anyhow!("to address: {e}"))?;
            let utxos = rpc.spendable(&my_addr)?;
            let mut selected: Vec<(OutPoint, Coin)> = Vec::new();
            let mut total = 0u64;
            for u in &utxos {
                let txid: Hash32 = hex::decode(u["txid"].as_str().unwrap())?.try_into().unwrap();
                let op = OutPoint::new(txid, u["vout"].as_u64().unwrap() as u32);
                let coin = Coin { output: Output { value: u["value"].as_u64().unwrap(), kind: my_kind.clone() }, height: u["height"].as_u64().unwrap() as u32, coinbase: u["coinbase"].as_bool().unwrap() };
                total += coin.output.value;
                selected.push((op, coin));
                if total >= amount + fee {
                    break;
                }
            }
            if total < amount + fee {
                bail!("insufficient funds: have {total}, need {}", amount + fee);
            }
            let mut outputs = vec![Output { value: amount, kind: to_kind }];
            if total - amount - fee > 0 {
                outputs.push(Output { value: total - amount - fee, kind: my_kind.clone() });
            }
            let mut tx = Transaction {
                version: Transaction::VERSION,
                inputs: selected.iter().map(|(op, _)| Input { prevout: *op, witness: Witness::Slh { signers: vec![] } }).collect(),
                outputs,
                locktime: 0,
                proofs: vec![],
            };
            let txid = tx.txid();
            for (i, (_, coin)) in selected.iter().enumerate() {
                let msg = slh_sighash(&genesis, &txid, i as u32, &coin.leaf_hash());
                let sig = sk.sign(&msg);
                tx.inputs[i].witness = Witness::Slh { signers: vec![SlhSigner { index: 0, pubkey: sk.public_key().0, signature: sig }] };
            }
            if corrupt_signature {
                if let Witness::Slh { signers } = &mut tx.inputs[0].witness {
                    signers[0].signature[1000] ^= 0x01;
                }
            }
            let r = rpc.call("sendrawtransaction", json!([hex::encode(tx.to_bytes())]))?;
            println!("{}", r.as_str().unwrap_or(""));
        }
        Cmd::LegacyScript { kind, keys, threshold } => {
            let ks: Vec<k256::SecretKey> = keys.iter().map(|k| secret_hex(k)).collect::<Result<_>>()?;
            let (spk, _) = legacy_script(kind, &ks, threshold)?;
            println!("{}", hex::encode(spk));
        }
        Cmd::Migrate { kind, keys, signers, threshold, txid, vout, to, fee, prove_mode, segment_po2 } => {
            let ks: Vec<k256::SecretKey> = keys.iter().map(|k| secret_hex(k)).collect::<Result<_>>()?;
            let (spk, script) = legacy_script(kind, &ks, threshold)?;
            let hrp = rpc.hrp()?;
            let genesis = rpc.genesis_hash()?;
            let to_kind = address::decode(&hrp, &to).map_err(|e| anyhow!("to address: {e}"))?;
            let txid_b: Hash32 = hex::decode(&txid)?.try_into().map_err(|_| anyhow!("txid"))?;
            let c = rpc.call("getcoin", json!([txid, vout]))?;
            let coin = Coin::from_bytes(&hex::decode(c["coin_hex"].as_str().unwrap_or(""))?).map_err(|e| anyhow!("coin: {e}"))?;
            match &coin.output.kind {
                OutputKind::Legacy { script_pubkey } if *script_pubkey == spk => {}
                OutputKind::Legacy { script_pubkey } => bail!("coin script {} does not match derived {}", hex::encode(script_pubkey), hex::encode(&spk)),
                _ => bail!("not a legacy coin"),
            }
            if coin.output.value <= fee {
                bail!("coin value {} does not cover fee {fee}", coin.output.value);
            }
            let tx = Transaction {
                version: Transaction::VERSION,
                inputs: vec![Input { prevout: OutPoint::new(txid_b, vout), witness: Witness::Legacy }],
                outputs: vec![Output { value: coin.output.value - fee, kind: to_kind }],
                locktime: 0,
                proofs: vec![],
            };
            let m = migration_msg(&genesis, &tx.txid(), 0, &coin.leaf_hash());
            let auth: MigrationAuth = match kind {
                LegacyKindArg::P2pkh | LegacyKindArg::P2wpkh | LegacyKindArg::P2shP2wpkh => lsign::auth_keyhash(&ks[0], &m, true),
                LegacyKindArg::P2pkhUncompressed => lsign::auth_keyhash(&ks[0], &m, false),
                LegacyKindArg::P2pk => lsign::auth_p2pk(&ks[0], &m),
                LegacyKindArg::P2tr => lsign::auth_taproot(&ks[0], &m),
                LegacyKindArg::P2wshMultisig | LegacyKindArg::P2shMultisig => {
                    let sks: Vec<k256::SecretKey> = signers.iter().map(|k| secret_hex(k)).collect::<Result<_>>()?;
                    let refs: Vec<&k256::SecretKey> = sks.iter().collect();
                    lsign::auth_multisig(script.as_ref().unwrap(), &refs, &m)
                }
            };
            let input = MigrationInput { msg: m, script_pubkey: spk, auth };
            let cfg = ProverConfig { mode: prove_mode, segment_po2: Some(segment_po2) };
            eprintln!("proving migration ({prove_mode:?})...");
            let started = std::time::Instant::now();
            let receipt = bhss_prover::prove_migration(&cfg, &input)?;
            eprintln!("migration receipt: {} bytes in {:.1}s", receipt.len(), started.elapsed().as_secs_f64());
            let mut tx = tx;
            tx.proofs = vec![receipt];
            let r = rpc.call("sendrawtransaction", json!([hex::encode(tx.to_bytes())]))?;
            println!("{}", r.as_str().unwrap_or(""));
        }
        Cmd::Rpc { method, params } => {
            let ps: Vec<Value> = params.iter().map(|p| serde_json::from_str(p).unwrap_or(Value::String(p.clone()))).collect();
            let r = rpc.call(&method, Value::Array(ps))?;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
    }
    Ok(())
}
