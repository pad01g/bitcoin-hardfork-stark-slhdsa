//! Minimal gossip network (NET-1..NET-4). Frames: u32 LE length + payload;
//! payload = tag byte + canonical encoding.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bhss_primitives::types::{Block, Transaction};
use bhss_primitives::{Decode, DecodeError, Decoder, Encode, Encoder, Hash32};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::chain::{Accept, ChainState};

pub const MAX_FRAME: usize = 64 << 20;
pub const BLOCKS_PER_REQUEST: u32 = 32;

#[derive(Clone, Debug)]
pub enum Message {
    Hello { network: String, genesis_hash: Hash32, height: u32, tip: Hash32 },
    Block(Block),
    Tx(Transaction),
    GetBlocks { from_height: u32, count: u32 },
    Blocks(Vec<Block>),
}

impl Encode for Message {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Message::Hello { network, genesis_hash, height, tip } => {
                e.u8(0).bytes(network.as_bytes()).raw(genesis_hash).u32(*height).raw(tip);
            }
            Message::Block(b) => {
                e.u8(1).item(b);
            }
            Message::Tx(t) => {
                e.u8(2).item(t);
            }
            Message::GetBlocks { from_height, count } => {
                e.u8(3).u32(*from_height).u32(*count);
            }
            Message::Blocks(bs) => {
                e.u8(4).vec(bs);
            }
        }
    }
}
impl Decode for Message {
    fn decode(d: &mut Decoder<'_>) -> std::result::Result<Self, DecodeError> {
        Ok(match d.u8()? {
            0 => Message::Hello {
                network: String::from_utf8(d.bytes()?).map_err(|_| DecodeError::InvalidValue("utf8"))?,
                genesis_hash: d.array()?,
                height: d.u32()?,
                tip: d.array()?,
            },
            1 => Message::Block(Block::decode(d)?),
            2 => Message::Tx(Transaction::decode(d)?),
            3 => Message::GetBlocks { from_height: d.u32()?, count: d.u32()? },
            4 => Message::Blocks(d.vec()?),
            t => return Err(DecodeError::InvalidTag(t)),
        })
    }
}

/// Relay envelope: `origin` is the peer id the message came from (0 = local).
#[derive(Clone)]
pub struct Relay {
    pub origin: u64,
    pub msg: Arc<Message>,
}

pub struct Network {
    pub chain: Arc<Mutex<ChainState>>,
    pub relay: broadcast::Sender<Relay>,
    pub peers: Arc<Mutex<Vec<(u64, SocketAddr)>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl Network {
    pub fn new(chain: Arc<Mutex<ChainState>>) -> Self {
        let (relay, _) = broadcast::channel(256);
        Self { chain, relay, peers: Arc::new(Mutex::new(Vec::new())), next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)) }
    }

    pub fn broadcast(&self, msg: Message) {
        let _ = self.relay.send(Relay { origin: 0, msg: Arc::new(msg) });
    }

    pub async fn listen(self: Arc<Self>, bind: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind).await?;
        tracing::info!(%bind, "p2p listening");
        loop {
            let (stream, addr) = listener.accept().await?;
            let net = self.clone();
            tokio::spawn(async move {
                if let Err(e) = net.run_peer(stream, addr).await {
                    tracing::debug!(%addr, "peer closed: {e:#}");
                }
            });
        }
    }

    /// Keep an outbound connection alive, reconnecting on failure.
    pub async fn connect_loop(self: Arc<Self>, target: String) {
        loop {
            match TcpStream::connect(&target).await {
                Ok(stream) => {
                    let addr = stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
                    tracing::info!(%target, "connected");
                    if let Err(e) = self.clone().run_peer(stream, addr).await {
                        tracing::warn!(%target, "peer error: {e:#}");
                    }
                }
                Err(e) => tracing::debug!(%target, "connect failed: {e}"),
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    fn hello(&self) -> Message {
        let c = self.chain.lock().unwrap();
        Message::Hello { network: c.params.name.clone(), genesis_hash: c.genesis_hash, height: c.height(), tip: c.tip.hash }
    }

    async fn run_peer(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.peers.lock().unwrap().push((id, addr));
        let result = self.clone().peer_session(id, stream).await;
        self.peers.lock().unwrap().retain(|(pid, _)| *pid != id);
        result
    }

    async fn peer_session(self: Arc<Self>, id: u64, stream: TcpStream) -> Result<()> {
        let (mut rd, mut wr) = stream.into_split();
        let mut rx = self.relay.subscribe();
        write_frame(&mut wr, &self.hello()).await?;
        let (tx_out, mut rx_out) = tokio::sync::mpsc::channel::<Message>(64);
        // Writer task: relayed messages + direct replies.
        let writer = tokio::spawn(async move {
            loop {
                tokio::select! {
                    r = rx.recv() => match r {
                        Ok(relay) if relay.origin != id => { if write_frame(&mut wr, &relay.msg).await.is_err() { break; } }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(_) => break,
                    },
                    m = rx_out.recv() => match m {
                        Some(m) => { if write_frame(&mut wr, &m).await.is_err() { break; } }
                        None => break,
                    },
                }
            }
        });
        let mut peer_height = 0u32;
        let outcome: Result<()> = async {
            loop {
                let msg = read_frame(&mut rd).await?;
                match msg {
                    Message::Hello { network, genesis_hash, height, .. } => {
                        let (ours_net, ours_gen, ours_h) = {
                            let c = self.chain.lock().unwrap();
                            (c.params.name.clone(), c.genesis_hash, c.height())
                        };
                        if network != ours_net || genesis_hash != ours_gen {
                            bail!("peer on a different network");
                        }
                        peer_height = height;
                        if height > ours_h {
                            tx_out.send(Message::GetBlocks { from_height: ours_h + 1, count: BLOCKS_PER_REQUEST }).await?;
                        }
                    }
                    Message::GetBlocks { from_height, count } => {
                        let blocks: Vec<Block> = {
                            let c = self.chain.lock().unwrap();
                            (from_height..from_height.saturating_add(count.min(BLOCKS_PER_REQUEST)))
                                .filter_map(|h| c.block_at(h).map(|b| (**b).clone()))
                                .collect()
                        };
                        if !blocks.is_empty() {
                            tx_out.send(Message::Blocks(blocks)).await?;
                        }
                    }
                    Message::Blocks(blocks) => {
                        for b in blocks {
                            self.handle_block(id, b, &tx_out).await?;
                        }
                        let ours_h = self.chain.lock().unwrap().height();
                        if peer_height > ours_h {
                            tx_out.send(Message::GetBlocks { from_height: ours_h + 1, count: BLOCKS_PER_REQUEST }).await?;
                        }
                    }
                    Message::Block(b) => {
                        self.handle_block(id, b, &tx_out).await?;
                    }
                    Message::Tx(t) => {
                        let r = self.chain.lock().unwrap().add_to_mempool(t.clone());
                        match r {
                            Ok(txid) => {
                                tracing::info!(txid = hex::encode(txid), "tx accepted from peer");
                                let _ = self.relay.send(Relay { origin: id, msg: Arc::new(Message::Tx(t)) });
                            }
                            Err(e) => tracing::debug!("tx from peer rejected: {e:#}"),
                        }
                    }
                }
            }
        }
        .await;
        writer.abort();
        outcome
    }

    async fn handle_block(&self, origin: u64, block: Block, tx_out: &tokio::sync::mpsc::Sender<Message>) -> Result<()> {
        let hash = block.hash();
        let height_hint = block.txs.first().map(|t| t.inputs[0].prevout.vout).unwrap_or(0);
        let (result, ours_h) = {
            let mut c = self.chain.lock().unwrap();
            let r = c.accept_block(block.clone(), true);
            (r, c.height())
        };
        match result {
            Ok(Accept::Connected) | Ok(Accept::Reorganized) => {
                tracing::info!(height = height_hint, hash = hex::encode(hash), "block accepted from peer");
                let _ = self.relay.send(Relay { origin, msg: Arc::new(Message::Block(block)) });
            }
            Ok(Accept::Orphan) => {
                // The peer is on a fork we have not seen: fetch a window that
                // reaches below our tip so the fork point is included (NET-3).
                let from = ours_h.saturating_sub(BLOCKS_PER_REQUEST - 1).max(1);
                tracing::debug!(hash = hex::encode(hash), from, "orphan block; requesting peer chain");
                tx_out.send(Message::GetBlocks { from_height: from, count: BLOCKS_PER_REQUEST }).await?;
            }
            Ok(Accept::AlreadyKnown) | Ok(Accept::SideChain) => {}
            Err(e) => tracing::warn!(hash = hex::encode(hash), "block from peer rejected: {e:#}"),
        }
        Ok(())
    }
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &Message) -> Result<()> {
    let payload = msg.to_bytes();
    w.write_all(&(payload.len() as u32).to_le_bytes()).await?;
    w.write_all(&payload).await?;
    w.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Message> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame too large");
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Message::from_bytes(&buf).map_err(|e| anyhow!("bad frame: {e}"))
}
