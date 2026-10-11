use std::path::PathBuf;

use anyhow::{Context, Result};
use bhss_primitives::types::OutPoint;
use bhss_primitives::ChainParams;
use bhss_snapshot::*;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bhss-snapshot", about = "Build a BHSS network definition (params.json + genesis_state.bin)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Genesis state from a Bitcoin Core `dumptxoutset` file.
    FromDump {
        #[arg(long)]
        dump: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value = "bhsn")]
        name: String,
        #[arg(long)]
        require_real_proofs: bool,
    },
    /// Empty genesis state (plain regtest).
    Empty {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value = "bhrt")]
        name: String,
    },
    /// Synthetic legacy coins: `--coin <txid_hex>:<vout>:<value>:<script_hex>` (repeatable).
    Synthetic {
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long, default_value = "bhrt")]
        name: String,
        #[arg(long = "coin")]
        coins: Vec<String>,
    },
    /// Print the SMT root of a genesis state file.
    Root {
        #[arg(long)]
        state: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::FromDump { dump, out_dir, name, require_real_proofs } => {
            let f = std::fs::File::open(&dump).with_context(|| format!("open {}", dump.display()))?;
            let (info, coins) = parse_dump(std::io::BufReader::new(f))?;
            eprintln!(
                "dumptxoutset v{} base_blockhash={} coins={} imported={} skipped={}",
                info.version,
                hex::encode(info.base_blockhash),
                info.coins_count,
                info.imported,
                info.skipped
            );
            let mut params = ChainParams::regtest([0u8; 32]);
            params.name = name;
            params.require_real_proofs = require_real_proofs;
            write_network(&out_dir, params, &coins)?;
            println!("{}", hex::encode(genesis_state_root(&coins)));
        }
        Cmd::Empty { out_dir, name } => {
            let mut params = ChainParams::regtest([0u8; 32]);
            params.name = name;
            write_network(&out_dir, params, &Vec::new())?;
            println!("{}", hex::encode(genesis_state_root(&Vec::new())));
        }
        Cmd::Synthetic { out_dir, name, coins } => {
            let mut genesis = GenesisCoins::new();
            for spec in coins {
                let parts: Vec<&str> = spec.split(':').collect();
                anyhow::ensure!(parts.len() == 4, "--coin expects txid:vout:value:script_hex");
                let txid: [u8; 32] = hex::decode(parts[0])?.try_into().map_err(|_| anyhow::anyhow!("txid must be 32 bytes"))?;
                let vout: u32 = parts[1].parse()?;
                let value: u64 = parts[2].parse()?;
                let script = hex::decode(parts[3])?;
                let coin = legacy_coin(value, script).context("unspendable script")?;
                genesis.push((OutPoint::new(txid, vout), coin));
            }
            let mut params = ChainParams::regtest([0u8; 32]);
            params.name = name;
            write_network(&out_dir, params, &genesis)?;
            println!("{}", hex::encode(genesis_state_root(&genesis)));
        }
        Cmd::Root { state } => {
            let coins = decode_genesis_state(&std::fs::read(state)?)?;
            println!("{}", hex::encode(genesis_state_root(&coins)));
        }
    }
    Ok(())
}
