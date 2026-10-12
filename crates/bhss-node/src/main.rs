//! bhssd — BHSS node.
mod chain;
mod miner;
mod p2p;
mod rpc;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use bhss_primitives::ChainParams;
use bhss_prover::{ProveMode, ProverConfig};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "bhssd", about = "BHSS regtest node")]
struct Args {
    #[arg(long, default_value = "data")]
    datadir: PathBuf,
    /// params.json produced by bhss-snapshot
    #[arg(long)]
    params: PathBuf,
    /// genesis_state.bin produced by bhss-snapshot
    #[arg(long)]
    genesis_state: PathBuf,
    #[arg(long, default_value = "127.0.0.1:18555")]
    p2p_bind: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:18443")]
    rpc_bind: SocketAddr,
    /// Outbound peers host:port (repeatable)
    #[arg(long = "connect")]
    connect: Vec<String>,
    /// Proof generation for blocks this node mines: dev (fake receipts) or real (STARK)
    #[arg(long, default_value = "dev")]
    prove_mode: ProveMode,
    /// RISC Zero segment size (power of two); lower values use less memory
    #[arg(long, default_value_t = 20)]
    segment_po2: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).init();
    let args = Args::parse();
    let params: ChainParams = serde_json::from_str(&std::fs::read_to_string(&args.params).context("read params")?)?;
    let coins = bhss_snapshot::decode_genesis_state(&std::fs::read(&args.genesis_state).context("read genesis state")?)?;
    let mut chain = chain::ChainState::new(params, coins, args.datadir.clone())?;
    chain.real_miner = args.prove_mode == ProveMode::Real;
    if bhss_prover::dev_mode_env() {
        tracing::warn!("RISC0_DEV_MODE is set in the environment; it is ignored by receipt verification (PRF-5) and refused by --prove-mode real");
    }
    let replayed = chain.load_from_disk()?;
    tracing::info!(
        network = chain.params.name,
        genesis = hex::encode(chain.genesis_hash),
        height = chain.height(),
        replayed,
        utxos = chain.state.coins.len(),
        block_image_id = hex::encode(bhss_prover::block_image_id()),
        migrate_image_id = hex::encode(bhss_prover::migrate_image_id()),
        "chain loaded"
    );
    let chain = Arc::new(Mutex::new(chain));
    let net = Arc::new(p2p::Network::new(chain.clone()));
    // Bind before spawning so a taken port is a startup error, not a node
    // that silently has no P2P.
    let p2p_listener = tokio::net::TcpListener::bind(args.p2p_bind).await.with_context(|| format!("bind p2p {}", args.p2p_bind))?;
    tracing::info!(bind = %args.p2p_bind, "p2p listening");
    tokio::spawn(net.clone().listen(p2p_listener));
    for target in args.connect {
        tokio::spawn(net.clone().connect_loop(target));
    }
    let ctx = rpc::RpcContext {
        chain,
        net,
        prover: ProverConfig { mode: args.prove_mode, segment_po2: Some(args.segment_po2) },
        mining: Arc::new(tokio::sync::Mutex::new(())),
    };
    let listener = tokio::net::TcpListener::bind(args.rpc_bind).await.with_context(|| format!("bind rpc {}", args.rpc_bind))?;
    tracing::info!(bind = %args.rpc_bind, "rpc listening");
    axum::serve(listener, rpc::router(ctx)).await?;
    Ok(())
}
