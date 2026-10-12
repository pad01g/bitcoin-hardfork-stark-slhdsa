//! Minimal gossip network (NET-1..NET-7). Frames: u32 LE length + payload;
//! payload = tag byte + canonical encoding.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bhss_primitives::types::{Block, Transaction};
use bhss_primitives::{Decode, DecodeError, Decoder, Encode, Encoder, Hash32};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::chain::{lock, Accept, ChainState};

/// Largest frame accepted: one block (≤ 32 MiB, BLK-12) or a `Blocks` reply
/// (8 MiB budget, which a single maximal block may exceed), with headroom.
pub const MAX_FRAME: usize = 48 << 20;
/// Byte budget of one `Blocks` reply (always at least one block).
pub const MAX_BLOCKS_REPLY_BYTES: usize = 8 << 20;
pub const BLOCKS_PER_REQUEST: u32 = 32;
/// Inbound connections served at once.
pub const MAX_PEERS: usize = 64;
/// Each side sends a `Ping` this often so an idle link is not mistaken for a
/// dead one.
pub const PING_INTERVAL: Duration = Duration::from_secs(60);
/// A peer silent for this long (several missed pings) is dropped.
pub const READ_TIMEOUT: Duration = Duration::from_secs(300);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// A peer that does not take one frame within this time is dropped, so a
/// peer that stops reading cannot hold replies in memory indefinitely.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub enum Message {
    Hello { network: String, genesis_hash: Hash32, params_hash: Hash32, height: u32, tip: Hash32 },
    Block(Block),
    Tx(Transaction),
    GetBlocks { from_height: u32, count: u32 },
    Blocks(Vec<Block>),
    Ping,
}

impl Message {
    pub fn tag_name(&self) -> &'static str {
        match self {
            Message::Hello { .. } => "Hello",
            Message::Block(_) => "Block",
            Message::Tx(_) => "Tx",
            Message::GetBlocks { .. } => "GetBlocks",
            Message::Blocks(_) => "Blocks",
            Message::Ping => "Ping",
        }
    }
}

impl Encode for Message {
    fn encode(&self, e: &mut Encoder) {
        match self {
            Message::Hello { network, genesis_hash, params_hash, height, tip } => {
                e.u8(0).bytes(network.as_bytes()).raw(genesis_hash).raw(params_hash).u32(*height).raw(tip);
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
            Message::Ping => {
                e.u8(5);
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
                params_hash: d.array()?,
                height: d.u32()?,
                tip: d.array()?,
            },
            1 => Message::Block(Block::decode(d)?),
            2 => Message::Tx(Transaction::decode(d)?),
            3 => Message::GetBlocks { from_height: d.u32()?, count: d.u32()? },
            4 => Message::Blocks(d.vec()?),
            5 => Message::Ping,
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
    next_id: AtomicU64,
    inbound: AtomicUsize,
}

/// Decrements the inbound counter when a session ends, however it ends.
struct InboundSlot(Arc<Network>);
impl Drop for InboundSlot {
    fn drop(&mut self) {
        self.0.inbound.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Per-peer block download state (NET-3). At most one `GetBlocks` is in
/// flight. The functions below are the whole policy; each returns the
/// height to request next, if any, and records the request.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SyncState {
    /// Height the peer announced in its `Hello`.
    peer_height: u32,
    pending: bool,
    /// Start of the last request.
    last_from: u32,
    /// Set while looking for the fork point with a peer whose blocks did
    /// not connect: the start of the lowest window requested so far.
    back_from: Option<u32>,
    /// A block with an unknown parent arrived while a request was in
    /// flight: the peer has grown past the height it announced.
    more: bool,
}

/// What a `Blocks` reply amounted to.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Reply {
    pub blocks: u32,
    /// At least one block extended or replaced the main chain.
    pub progressed: bool,
    /// At least one block had an unknown parent.
    pub orphaned: bool,
    /// At least one block was invalid.
    pub rejected: bool,
}

impl SyncState {
    fn request(&mut self, from: u32) -> Option<u32> {
        self.pending = true;
        self.last_from = from;
        Some(from)
    }

    pub(crate) fn on_hello(&mut self, peer_height: u32, ours: u32) -> Option<u32> {
        self.peer_height = peer_height;
        if peer_height > ours && !self.pending {
            return self.request(ours + 1);
        }
        None
    }

    /// A block with an unknown parent arrived: the peer is on a branch we
    /// do not have. Ask for the 32 heights ending at our tip, so that the
    /// fork point is covered; every further miss moves the window down.
    pub(crate) fn on_orphan(&mut self, ours: u32) -> Option<u32> {
        if self.pending {
            self.more = true;
            return None;
        }
        let from = match self.back_from {
            None => ours.saturating_sub(BLOCKS_PER_REQUEST - 1).max(1),
            Some(f) if f <= 1 => {
                // Even the window starting at height 1 did not connect.
                self.back_from = None;
                return None;
            }
            Some(f) => f.saturating_sub(BLOCKS_PER_REQUEST).max(1),
        };
        self.back_from = Some(from);
        self.request(from)
    }

    pub(crate) fn on_reply(&mut self, r: Reply, ours: u32) -> Option<u32> {
        self.pending = false;
        let more = std::mem::take(&mut self.more);
        if r.progressed {
            // Back on the peer's chain: continue from our (new) tip, also
            // when the peer mined past its announced height meanwhile (an
            // empty reply then ends the exchange).
            self.back_from = None;
            return if self.peer_height > ours || more { self.request(ours.saturating_add(1)) } else { None };
        }
        if r.rejected {
            // Nothing good comes after an invalid block of this peer.
            self.back_from = None;
            return None;
        }
        if r.orphaned {
            return self.on_orphan(ours);
        }
        // Everything was already known or went to a side branch. If we are
        // looking for (or still behind) the peer's chain, walk forward: the
        // blocks above the fork point are stored now, so the ones that
        // follow will connect or reorganize.
        if r.blocks > 0 && (self.back_from.is_some() || self.peer_height > ours) {
            return self.request(self.last_from.saturating_add(r.blocks));
        }
        self.back_from = None;
        None
    }
}

impl Network {
    pub fn new(chain: Arc<Mutex<ChainState>>) -> Self {
        let (relay, _) = broadcast::channel(256);
        Self { chain, relay, peers: Arc::new(Mutex::new(Vec::new())), next_id: AtomicU64::new(1), inbound: AtomicUsize::new(0) }
    }

    pub fn broadcast(&self, msg: Message) {
        let _ = self.relay.send(Relay { origin: 0, msg: Arc::new(msg) });
    }

    pub async fn listen(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    // EMFILE / ECONNABORTED must not kill the listener.
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            if self.inbound.load(Ordering::Relaxed) >= MAX_PEERS {
                tracing::debug!(%addr, "inbound peer limit reached, dropping");
                continue;
            }
            self.inbound.fetch_add(1, Ordering::Relaxed);
            let slot = InboundSlot(self.clone());
            let net = self.clone();
            tokio::spawn(async move {
                let _slot = slot;
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
        let c = lock(&self.chain);
        Message::Hello { network: c.params.name.clone(), genesis_hash: c.genesis_hash, params_hash: c.params_hash, height: c.height(), tip: c.tip.hash }
    }

    fn our_height(&self) -> u32 {
        lock(&self.chain).height()
    }

    fn peer_list(&self) -> std::sync::MutexGuard<'_, Vec<(u64, SocketAddr)>> {
        self.peers.lock().unwrap_or_else(|e| e.into_inner())
    }

    async fn run_peer(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.peer_list().push((id, addr));
        let result = self.clone().peer_session(id, stream).await;
        self.peer_list().retain(|(pid, _)| *pid != id);
        result
    }

    async fn peer_session(self: Arc<Self>, id: u64, stream: TcpStream) -> Result<()> {
        let (mut rd, mut wr) = stream.into_split();
        let mut rx = self.relay.subscribe();
        write_frame(&mut wr, &self.hello()).await?;
        // Direct replies. A `Blocks` reply carries a permit of `reply_slot`,
        // released once it is written: at most one is ever queued per peer.
        let (tx_out, mut rx_out) = tokio::sync::mpsc::channel::<(Message, Option<tokio::sync::OwnedSemaphorePermit>)>(64);
        let reply_slot = Arc::new(tokio::sync::Semaphore::new(1));
        // Writer task: relayed messages, direct replies and keep-alives.
        let mut writer = tokio::spawn(async move {
            let mut ping = tokio::time::interval(PING_INTERVAL);
            ping.tick().await; // the first tick is immediate
            loop {
                tokio::select! {
                    r = rx.recv() => match r {
                        Ok(relay) if relay.origin != id => { if write_frame(&mut wr, &relay.msg).await.is_err() { break; } }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(n)) => { tracing::warn!(peer = id, "relay lagged, {n} messages dropped"); }
                        Err(_) => break,
                    },
                    m = rx_out.recv() => match m {
                        Some((m, _permit)) => { if write_frame(&mut wr, &m).await.is_err() { break; } }
                        None => break,
                    },
                    _ = ping.tick() => { if write_frame(&mut wr, &Message::Ping).await.is_err() { break; } }
                }
            }
        });
        let request = |from: Option<u32>| from.map(|from_height| Message::GetBlocks { from_height, count: BLOCKS_PER_REQUEST });
        let mut sync = SyncState::default();
        let mut greeted = false;
        let outcome: Result<()> = async {
            loop {
                let timeout = if greeted { READ_TIMEOUT } else { HANDSHAKE_TIMEOUT };
                // The session ends with its writer (write error or timeout).
                let msg = tokio::select! {
                    _ = &mut writer => bail!("peer stopped reading"),
                    m = tokio::time::timeout(timeout, read_frame(&mut rd)) => m.map_err(|_| anyhow!("peer timed out"))??,
                };
                if !greeted && !matches!(msg, Message::Hello { .. }) {
                    bail!("peer sent {} before Hello (NET-7)", msg.tag_name());
                }
                let next = match msg {
                    Message::Hello { network, genesis_hash, params_hash, height, .. } => {
                        greeted = true;
                        let (ours_net, ours_gen, ours_params, ours_h) = {
                            let c = lock(&self.chain);
                            (c.params.name.clone(), c.genesis_hash, c.params_hash, c.height())
                        };
                        if network != ours_net || genesis_hash != ours_gen || params_hash != ours_params {
                            bail!("peer on a different network (NET-2)");
                        }
                        sync.on_hello(height, ours_h)
                    }
                    Message::GetBlocks { from_height, count } => {
                        // Wait for the previous reply to leave before
                        // building the next one.
                        let permit = tokio::select! {
                            _ = &mut writer => bail!("peer stopped reading"),
                            p = reply_slot.clone().acquire_owned() => p?,
                        };
                        let blocks: Vec<Block> = {
                            let c = lock(&self.chain);
                            let mut out = Vec::new();
                            let mut bytes = 0usize;
                            for h in from_height..from_height.saturating_add(count.min(BLOCKS_PER_REQUEST)) {
                                let Some(b) = c.block_at(h) else { break };
                                let n = b.to_bytes().len();
                                if !out.is_empty() && bytes + n > MAX_BLOCKS_REPLY_BYTES {
                                    break;
                                }
                                bytes += n;
                                out.push((**b).clone());
                            }
                            out
                        };
                        // Always answer, even with nothing: the requester
                        // keeps one request in flight and needs the reply to
                        // move on (NET-3).
                        tx_out.send((Message::Blocks(blocks), Some(permit))).await?;
                        None
                    }
                    Message::Blocks(blocks) => {
                        let mut reply = Reply { blocks: blocks.len() as u32, ..Reply::default() };
                        for b in blocks {
                            match self.handle_block(id, b).await? {
                                Accept::Connected | Accept::Reorganized => reply.progressed = true,
                                Accept::Orphan => reply.orphaned = true,
                                Accept::Rejected => reply.rejected = true,
                                Accept::AlreadyKnown | Accept::SideChain => {}
                            }
                        }
                        sync.on_reply(reply, self.our_height())
                    }
                    Message::Block(b) => match self.handle_block(id, b).await? {
                        Accept::Orphan => sync.on_orphan(self.our_height()),
                        _ => None,
                    },
                    Message::Tx(t) => {
                        let chain = self.chain.clone();
                        let t2 = t.clone();
                        let r = tokio::task::spawn_blocking(move || lock(&chain).add_to_mempool(t2)).await?;
                        match r {
                            Ok((txid, true)) => {
                                tracing::info!(txid = hex::encode(txid), "tx accepted from peer");
                                let _ = self.relay.send(Relay { origin: id, msg: Arc::new(Message::Tx(t)) });
                            }
                            Ok((_, false)) => {}
                            Err(e) => tracing::debug!("tx from peer rejected: {e:#}"),
                        }
                        None
                    }
                    Message::Ping => None,
                };
                if let Some(m) = request(next) {
                    tx_out.send((m, None)).await?;
                }
            }
        }
        .await;
        writer.abort();
        outcome
    }

    async fn handle_block(&self, origin: u64, block: Block) -> Result<Accept> {
        let hash = block.hash();
        let chain = self.chain.clone();
        let b = block.clone();
        // Validation (STARK verify + native checks) runs on the blocking pool
        // so that slow blocks do not stall the async runtime.
        let result = tokio::task::spawn_blocking(move || lock(&chain).accept_block(b, true)).await?;
        match result {
            Ok(a @ (Accept::Connected | Accept::Reorganized)) => {
                tracing::info!(hash = hex::encode(hash), ?a, "block accepted from peer");
                let _ = self.relay.send(Relay { origin, msg: Arc::new(Message::Block(block)) });
                Ok(a)
            }
            Ok(a) => Ok(a),
            Err(e) => {
                tracing::warn!(hash = hex::encode(hash), "block from peer rejected: {e:#}");
                Ok(Accept::Rejected)
            }
        }
    }
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &Message) -> Result<()> {
    let payload = msg.to_bytes();
    if payload.len() > MAX_FRAME {
        bail!("refusing to send a {} byte frame", payload.len());
    }
    let write = async {
        w.write_all(&(payload.len() as u32).to_le_bytes()).await?;
        w.write_all(&payload).await?;
        w.flush().await
    };
    tokio::time::timeout(WRITE_TIMEOUT, write).await.map_err(|_| anyhow!("write timed out"))??;
    Ok(())
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Message> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame too large");
    }
    let mut buf = Vec::new();
    // Grow with the data instead of trusting the length prefix up front.
    (&mut *r).take(len as u64).read_to_end(&mut buf).await?;
    if buf.len() != len {
        bail!("short frame");
    }
    Message::from_bytes(&buf).map_err(|e| anyhow!("bad frame: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: Reply = Reply { blocks: 32, progressed: false, orphaned: false, rejected: false };

    #[test]
    fn plain_catch_up() {
        let mut s = SyncState::default();
        assert_eq!(s.on_hello(100, 10), Some(11));
        // Nothing else goes out while the request is in flight.
        assert_eq!(s.on_orphan(10), None);
        assert_eq!(s.on_reply(Reply { progressed: true, ..KNOWN }, 42), Some(43));
        assert_eq!(s.on_reply(Reply { blocks: 2, progressed: true, ..KNOWN }, 100), None);
        assert_eq!(s, SyncState { peer_height: 100, pending: false, last_from: 43, back_from: None, more: false });
        // A peer that is not ahead is not asked for anything.
        assert_eq!(SyncState::default().on_hello(5, 5), None);
        // An empty reply ends the exchange.
        let mut s = SyncState::default();
        assert_eq!(s.on_hello(100, 10), Some(11));
        assert_eq!(s.on_reply(Reply { blocks: 0, ..KNOWN }, 10), None);
        assert!(!s.pending);
    }

    /// The peer mines block 21 while we download up to its announced height
    /// 20: the relayed block is an orphan at that moment and must not be lost.
    #[test]
    fn peer_grows_during_catch_up() {
        let mut s = SyncState::default();
        assert_eq!(s.on_hello(20, 10), Some(11));
        assert_eq!(s.on_orphan(12), None);
        assert_eq!(s.on_reply(Reply { blocks: 10, progressed: true, ..KNOWN }, 20), Some(21));
        assert_eq!(s.on_reply(Reply { blocks: 1, progressed: true, ..KNOWN }, 21), None);
        // Had the orphan been a block of some other branch, the extra
        // request is answered with nothing and the exchange ends.
        let mut s = SyncState::default();
        assert_eq!(s.on_hello(20, 10), Some(11));
        assert_eq!(s.on_orphan(12), None);
        assert_eq!(s.on_reply(Reply { blocks: 10, progressed: true, ..KNOWN }, 20), Some(21));
        assert_eq!(s.on_reply(Reply { blocks: 0, ..KNOWN }, 20), None);
        assert!(!s.pending && !s.more);
    }

    /// We are at height 100 on branch A; the peer is at 102 on branch B that
    /// forked at 99. This stalled before the forward walk existed.
    #[test]
    fn shallow_fork_on_a_long_chain() {
        let mut s = SyncState::default();
        assert_eq!(s.on_hello(102, 100), Some(101));
        // B101's parent B100 is unknown.
        assert_eq!(s.on_reply(Reply { blocks: 2, orphaned: true, ..KNOWN }, 100), Some(69));
        // 69..=100: all known except B100, which becomes a side block.
        assert_eq!(s.on_reply(KNOWN, 100), Some(101));
        // B101 now reorganizes, B102 connects.
        assert_eq!(s.on_reply(Reply { blocks: 2, progressed: true, ..KNOWN }, 102), None);
        assert_eq!(s.back_from, None);
    }

    /// Fork point 60 blocks below our tip: two windows back, then forward.
    #[test]
    fn deep_fork() {
        let mut s = SyncState::default();
        assert_eq!(s.on_hello(105, 100), Some(101));
        assert_eq!(s.on_reply(Reply { blocks: 5, orphaned: true, ..KNOWN }, 100), Some(69));
        // B69's parent is unknown too.
        assert_eq!(s.on_reply(Reply { orphaned: true, ..KNOWN }, 100), Some(37));
        // 37..=68 covers the fork point at 40: side blocks, no orphans.
        assert_eq!(s.on_reply(KNOWN, 100), Some(69));
        assert_eq!(s.on_reply(KNOWN, 100), Some(101));
        assert_eq!(s.on_reply(Reply { blocks: 5, progressed: true, ..KNOWN }, 105), None);
    }

    #[test]
    fn relayed_orphan_and_dead_ends() {
        // A relayed block with an unknown parent starts the walk.
        let mut s = SyncState::default();
        assert_eq!(s.on_orphan(10), Some(1));
        assert_eq!(s.back_from, Some(1));
        // The window from height 1 did not connect either: give up, reset.
        assert_eq!(s.on_reply(Reply { orphaned: true, ..KNOWN }, 10), None);
        assert_eq!(s.back_from, None);
        // An invalid block ends a walk.
        let mut s = SyncState::default();
        assert_eq!(s.on_orphan(100), Some(69));
        assert_eq!(s.on_reply(Reply { rejected: true, ..KNOWN }, 100), None);
        assert_eq!(s, SyncState { peer_height: 0, pending: false, last_from: 69, back_from: None, more: false });
        // In sync with the peer: a reply of known blocks asks for nothing.
        let mut s = SyncState { peer_height: 100, ..SyncState::default() };
        assert_eq!(s.on_reply(KNOWN, 100), None);
    }

    #[test]
    fn message_roundtrip() {
        for m in [Message::Ping, Message::GetBlocks { from_height: 7, count: 32 }, Message::Blocks(vec![]), Message::Hello { network: "bhrt".into(), genesis_hash: [1; 32], params_hash: [2; 32], height: 9, tip: [3; 32] }] {
            let bytes = m.to_bytes();
            assert_eq!(Message::from_bytes(&bytes).unwrap().to_bytes(), bytes);
        }
        assert!(Message::from_bytes(&[6]).is_err());
        assert!(Message::from_bytes(&[5, 0]).is_err(), "trailing bytes");
    }

    /// A node on an ephemeral port, and a raw connection to it that has
    /// already read the node's `Hello`.
    async fn node_and_socket() -> (Arc<Network>, TcpStream, Message) {
        let net = Arc::new(Network::new(Arc::new(Mutex::new(crate::chain::tests::chain()))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(net.clone().listen(listener));
        let mut sock = TcpStream::connect(addr).await.unwrap();
        let hello = read_frame(&mut sock).await.unwrap();
        (net, sock, hello)
    }

    async fn is_closed(sock: &mut TcpStream) -> bool {
        // The node drops the connection: the next read ends (or errors)
        // instead of yielding a frame.
        matches!(tokio::time::timeout(Duration::from_secs(10), read_frame(sock)).await, Ok(Err(_)))
    }

    #[tokio::test]
    async fn handshake_rules() {
        // NET-7: anything before Hello disconnects.
        let (_net, mut sock, hello) = node_and_socket().await;
        assert!(matches!(hello, Message::Hello { .. }));
        write_frame(&mut sock, &Message::Ping).await.unwrap();
        assert!(is_closed(&mut sock).await);

        // NET-2: a Hello with different parameters disconnects.
        let (_net, mut sock, hello) = node_and_socket().await;
        let Message::Hello { network, genesis_hash, params_hash, height, tip } = hello else { panic!("expected Hello") };
        let mut other = params_hash;
        other[0] ^= 1;
        write_frame(&mut sock, &Message::Hello { network: network.clone(), genesis_hash, params_hash: other, height, tip }).await.unwrap();
        assert!(is_closed(&mut sock).await);

        // A matching Hello is accepted: the peer is listed and a GetBlocks
        // is answered (with an empty list for heights the node lacks).
        let (net, mut sock, _) = node_and_socket().await;
        write_frame(&mut sock, &Message::Hello { network, genesis_hash, params_hash, height, tip }).await.unwrap();
        write_frame(&mut sock, &Message::GetBlocks { from_height: 1, count: 32 }).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut sock)).await.unwrap().unwrap();
        assert!(matches!(reply, Message::Blocks(ref b) if b.is_empty()), "{}", reply.tag_name());
        assert_eq!(net.peer_list().len(), 1);
        // Garbage ends the session.
        sock.write_all(&[1, 0, 0, 0, 0xee]).await.unwrap();
        assert!(is_closed(&mut sock).await);
    }
}
