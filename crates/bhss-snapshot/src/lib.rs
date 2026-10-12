//! GEN-2/GEN-3: turning a Bitcoin Core `dumptxoutset` file into the BHSS
//! genesis state, plus helpers to build synthetic states for tests.

use std::io::Read;

use anyhow::{bail, Context, Result};
use bhss_primitives::types::{Coin, OutPoint, Output, OutputKind};
use bhss_primitives::{ChainParams, Decode, Hash32};
use k256::elliptic_curve::sec1::ToEncodedPoint;

pub type GenesisCoins = Vec<(OutPoint, Coin)>;

/// GEN-3: imported coins get `height = 0`, `coinbase = false`, and their
/// scriptPubKey wrapped as `OutputKind::Legacy`. Unspendable scripts
/// (OP_RETURN, empty) are dropped (GEN-4).
pub fn legacy_coin(value: u64, script_pubkey: Vec<u8>) -> Option<Coin> {
    if script_pubkey.is_empty() || script_pubkey[0] == 0x6a || script_pubkey.len() > bhss_primitives::types::MAX_LEGACY_SCRIPT_LEN {
        return None;
    }
    Some(Coin { output: Output { value, kind: OutputKind::Legacy { script_pubkey } }, height: 0, coinbase: false })
}

pub fn encode_genesis_state(coins: &GenesisCoins) -> Vec<u8> {
    let mut sorted = coins.clone();
    sorted.sort_by_key(|c| c.0);
    let mut e = bhss_primitives::Encoder::new();
    e.vec(&sorted);
    e.finish()
}

pub fn decode_genesis_state(bytes: &[u8]) -> Result<GenesisCoins> {
    let v: Vec<(OutPoint, Coin)> = Vec::from_bytes(bytes).map_err(|e| anyhow::anyhow!("genesis state decode: {e}"))?;
    check_genesis_coins(&v)?;
    Ok(v)
}

pub fn genesis_state_root(coins: &GenesisCoins) -> Hash32 {
    bhss_consensus::genesis::genesis_state_root(coins)
}

/// Write `params.json` and `genesis_state.bin` into `dir`.
pub fn write_network(dir: &std::path::Path, mut params: ChainParams, coins: &GenesisCoins) -> Result<()> {
    check_genesis_coins(coins)?;
    std::fs::create_dir_all(dir)?;
    params.genesis_state_root = genesis_state_root(coins);
    std::fs::write(dir.join("genesis_state.bin"), encode_genesis_state(coins))?;
    std::fs::write(dir.join("params.json"), serde_json::to_string_pretty(&params)?)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Bitcoin Core dumptxoutset parser
// ---------------------------------------------------------------------------

struct Reader<R: Read> {
    r: R,
}

impl<R: Read> Reader<R> {
    fn u8(&mut self) -> Result<u8> {
        let mut b = [0u8; 1];
        self.r.read_exact(&mut b)?;
        Ok(b[0])
    }
    fn bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut v = vec![0u8; n];
        self.r.read_exact(&mut v)?;
        Ok(v)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.bytes(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.bytes(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.bytes(8)?.try_into().unwrap()))
    }
    /// Bitcoin CompactSize with Core's `ReadCompactSize` checks (canonical
    /// encoding, `MAX_SIZE` bound).
    fn compact(&mut self) -> Result<u64> {
        const MAX_SIZE: u64 = 0x0200_0000;
        let v = match self.u8()? {
            n @ 0..=0xfc => n as u64,
            0xfd => {
                let v = self.u16()? as u64;
                anyhow::ensure!(v >= 0xfd, "non-canonical CompactSize");
                v
            }
            0xfe => {
                let v = self.u32()? as u64;
                anyhow::ensure!(v > 0xffff, "non-canonical CompactSize");
                v
            }
            _ => {
                let v = self.u64()?;
                anyhow::ensure!(v > 0xffff_ffff, "non-canonical CompactSize");
                v
            }
        };
        anyhow::ensure!(v <= MAX_SIZE, "CompactSize {v} exceeds MAX_SIZE");
        Ok(v)
    }
    /// Bitcoin serialization VARINT (MSB base-128 with +1 continuation),
    /// with Core's overflow checks.
    fn varint(&mut self) -> Result<u64> {
        let mut n: u64 = 0;
        loop {
            let ch = self.u8()?;
            anyhow::ensure!(n <= (u64::MAX >> 7), "VARINT overflow");
            n = (n << 7) | (ch & 0x7f) as u64;
            if ch & 0x80 != 0 {
                anyhow::ensure!(n != u64::MAX, "VARINT overflow");
                n += 1;
            } else {
                return Ok(n);
            }
        }
    }
}

/// Core's `DecompressAmount`; `None` if the value does not fit (Core wraps,
/// but no real snapshot contains such a value and AMT-1 would reject it).
pub fn decompress_amount(mut x: u64) -> Option<u64> {
    if x == 0 {
        return Some(0);
    }
    x -= 1;
    let mut e = x % 10;
    x /= 10;
    let mut n = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x.checked_mul(10)?.checked_add(d)?
    } else {
        x.checked_add(1)?
    };
    while e > 0 {
        n = n.checked_mul(10)?;
        e -= 1;
    }
    Some(n)
}

/// Core's `DecompressScript`.
fn decompress_script<R: Read>(r: &mut Reader<R>) -> Result<Vec<u8>> {
    let n_size = r.varint()?;
    Ok(match n_size {
        0 => {
            let h = r.bytes(20)?;
            let mut s = vec![0x76, 0xa9, 0x14];
            s.extend(h);
            s.extend([0x88, 0xac]);
            s
        }
        1 => {
            let h = r.bytes(20)?;
            let mut s = vec![0xa9, 0x14];
            s.extend(h);
            s.push(0x87);
            s
        }
        2 | 3 => {
            let x = r.bytes(32)?;
            let mut s = vec![0x21, n_size as u8];
            s.extend(x);
            s.push(0xac);
            s
        }
        4 | 5 => {
            let x = r.bytes(32)?;
            let mut sec1 = vec![(n_size - 2) as u8];
            sec1.extend(&x);
            let pk = k256::PublicKey::from_sec1_bytes(&sec1).context("invalid compressed pubkey in snapshot")?;
            let mut s = vec![0x41];
            s.extend_from_slice(pk.to_encoded_point(false).as_bytes());
            s.push(0xac);
            s
        }
        n => {
            let len = (n - 6) as usize;
            // Core never serializes a script above MAX_SCRIPT_SIZE; anything
            // larger is a corrupt file, not a coin to import.
            if len > bhss_primitives::types::MAX_LEGACY_SCRIPT_LEN {
                bail!("script of {len} bytes in snapshot exceeds MAX_LEGACY_SCRIPT_LEN");
            }
            r.bytes(len)?
        }
    })
}

#[derive(Debug)]
pub struct DumpInfo {
    pub version: u16,
    pub base_blockhash: [u8; 32],
    pub coins_count: u64,
    pub imported: u64,
    pub skipped: u64,
}

/// Parse a `dumptxoutset` file (format v1 or v2) into genesis coins.
pub fn parse_dump<R: Read>(input: R) -> Result<(DumpInfo, GenesisCoins)> {
    let mut r = Reader { r: input };
    let mut head = r.bytes(5)?;
    let (version, base_blockhash): (u16, [u8; 32]) = if head == b"utxo\xff" {
        let version = r.u16()?;
        if version != 2 {
            bail!("unsupported dumptxoutset version {version}");
        }
        let _network_magic = r.bytes(4)?;
        (version, r.bytes(32)?.try_into().unwrap())
    } else {
        // v1: no magic; the first 32 bytes are the base block hash.
        head.extend(r.bytes(27)?);
        (1, head.try_into().unwrap())
    };
    let coins_count = r.u64()?;
    let mut coins = Vec::with_capacity(coins_count.min(1 << 16) as usize);
    let mut imported = 0u64;
    let mut skipped = 0u64;
    let mut read_coin = |r: &mut Reader<R>, txid: [u8; 32], vout: u32, coins: &mut GenesisCoins| -> Result<()> {
        let _code = r.varint()?; // height << 1 | coinbase (dropped, GEN-3)
        let value = decompress_amount(r.varint()?).context("amount overflow in snapshot")?;
        let script = decompress_script(r)?;
        match legacy_coin(value, script) {
            Some(c) => {
                coins.push((OutPoint::new(txid, vout), c));
                imported += 1;
            }
            None => skipped += 1,
        }
        Ok(())
    };
    if version == 2 {
        let mut seen = 0u64;
        while seen < coins_count {
            let txid: [u8; 32] = r.bytes(32)?.try_into().unwrap();
            let n = r.compact()?;
            anyhow::ensure!(n <= coins_count - seen, "coin group of {n} exceeds the remaining {} coins", coins_count - seen);
            for _ in 0..n {
                let vout = u32::try_from(r.compact()?).context("vout does not fit u32")?;
                read_coin(&mut r, txid, vout, &mut coins)?;
                seen += 1;
            }
        }
    } else {
        for _ in 0..coins_count {
            let txid: [u8; 32] = r.bytes(32)?.try_into().unwrap();
            let vout = r.u32()?;
            read_coin(&mut r, txid, vout, &mut coins)?;
        }
    }
    let mut trailing = [0u8; 1];
    anyhow::ensure!(r.r.read(&mut trailing)? == 0, "trailing bytes after the last coin");
    check_genesis_coins(&coins)?;
    Ok((DumpInfo { version, base_blockhash, coins_count, imported, skipped }, coins))
}

/// GEN-2 preconditions: outpoints are unique and the total value is within
/// AMT-1 (so no later sum of inputs can overflow or exceed MAX_MONEY).
pub fn check_genesis_coins(coins: &GenesisCoins) -> Result<()> {
    let mut seen = std::collections::HashSet::with_capacity(coins.len());
    let mut total: u64 = 0;
    for (op, coin) in coins {
        if !seen.insert(*op) {
            bail!("GEN-2: duplicate outpoint {}:{} in genesis state", hex::encode(op.txid), op.vout);
        }
        if !coin.output.kind.is_legacy() || !coin.output.kind.is_well_formed() || coin.height != 0 || coin.coinbase {
            bail!("GEN-2: genesis coin {}:{} is not a well-formed Legacy coin at height 0", hex::encode(op.txid), op.vout);
        }
        total = total.checked_add(coin.output.value).filter(|t| *t <= bhss_primitives::types::MAX_MONEY).ok_or_else(|| anyhow::anyhow!("GEN-2: genesis state total exceeds MAX_MONEY"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varint_bytes(mut n: u64) -> Vec<u8> {
        // Core's WriteVarInt
        let mut tmp = Vec::new();
        loop {
            tmp.push((n & 0x7f) as u8 | if tmp.is_empty() { 0 } else { 0x80 });
            if n <= 0x7f {
                break;
            }
            n = (n >> 7) - 1;
        }
        tmp.reverse();
        tmp
    }

    fn compress_amount(mut n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        let mut e = 0;
        while n.is_multiple_of(10) && e < 9 {
            n /= 10;
            e += 1;
        }
        if e < 9 {
            let d = n % 10;
            n /= 10;
            1 + (n * 9 + d - 1) * 10 + e
        } else {
            1 + (n - 1) * 10 + 9
        }
    }

    #[test]
    fn amount_roundtrip() {
        for v in [0u64, 1, 10, 12345, 50_0000_0000, 21_0000_0000_0000_0000 / 1000, 123456789] {
            assert_eq!(decompress_amount(compress_amount(v)), Some(v));
        }
        // Vectors from Bitcoin Core's compress_tests.cpp (CENT = 1_000_000,
        // COIN = 100_000_000).
        assert_eq!(compress_amount(0), 0);
        assert_eq!(compress_amount(1), 1);
        assert_eq!(compress_amount(1_000_000), 0x7);
        assert_eq!(compress_amount(100_000_000), 0x9);
        assert_eq!(compress_amount(50 * 100_000_000), 0x32);
        assert_eq!(compress_amount(21_000_000 * 100_000_000), 0x1406f40);
        assert_eq!(decompress_amount(u64::MAX), None);
    }

    #[test]
    fn parse_v2_dump() {
        let mut d = Vec::new();
        d.extend(b"utxo\xff");
        d.extend(2u16.to_le_bytes());
        d.extend([0x0a, 0x03, 0xcf, 0x40]); // signet magic
        d.extend([7u8; 32]);
        d.extend(3u64.to_le_bytes());
        // txid A with two outputs: P2PKH (compressed script type 0) and OP_RETURN (raw)
        d.extend([1u8; 32]);
        d.push(2);
        d.push(0); // vout 0
        d.extend(varint_bytes(100 << 1));
        d.extend(varint_bytes(compress_amount(5000)));
        d.extend(varint_bytes(0));
        d.extend([0xaa; 20]);
        d.push(1); // vout 1
        d.extend(varint_bytes(100 << 1));
        d.extend(varint_bytes(compress_amount(0)));
        let raw = vec![0x6a, 0x02, 0x01, 0x02];
        d.extend(varint_bytes(raw.len() as u64 + 6));
        d.extend(&raw);
        // txid B: P2WPKH raw script
        d.extend([2u8; 32]);
        d.push(1);
        d.push(5);
        d.extend(varint_bytes((7 << 1) | 1));
        d.extend(varint_bytes(compress_amount(123456789)));
        let raw = [vec![0x00, 0x14], vec![0xbb; 20]].concat();
        d.extend(varint_bytes(raw.len() as u64 + 6));
        d.extend(&raw);

        let (info, coins) = parse_dump(&d[..]).unwrap();
        assert_eq!(info.version, 2);
        assert_eq!(info.coins_count, 3);
        assert_eq!(info.imported, 2);
        assert_eq!(info.skipped, 1);
        assert_eq!(coins[0].0, OutPoint::new([1u8; 32], 0));
        assert_eq!(coins[0].1.output.value, 5000);
        assert_eq!(coins[0].1.output.kind, OutputKind::Legacy { script_pubkey: [vec![0x76, 0xa9, 0x14], vec![0xaa; 20], vec![0x88, 0xac]].concat() });
        assert_eq!(coins[1].0, OutPoint::new([2u8; 32], 5));
        assert_eq!(coins[1].1.output.value, 123456789);
        assert_eq!(coins[1].1.height, 0);
        assert!(!coins[1].1.coinbase);
        let enc = encode_genesis_state(&coins);
        assert_eq!(decode_genesis_state(&enc).unwrap(), coins);
    }

    #[test]
    fn genesis_preconditions() {
        let coin = |v: u64| legacy_coin(v, vec![0x00, 0x14, 0xaa]).unwrap();
        let op = |i: u8| OutPoint::new([i; 32], 0);
        assert!(check_genesis_coins(&vec![(op(1), coin(5)), (op(2), coin(6))]).is_ok());
        let err = |c: GenesisCoins| check_genesis_coins(&c).unwrap_err().to_string();
        assert!(err(vec![(op(1), coin(5)), (op(1), coin(6))]).contains("duplicate outpoint"));
        assert!(err(vec![(op(1), coin(bhss_primitives::types::MAX_MONEY)), (op(2), coin(1))]).contains("MAX_MONEY"));
        let mut c = coin(5);
        c.height = 1;
        assert!(err(vec![(op(1), c)]).contains("GEN-2"));
        let mut c = coin(5);
        c.coinbase = true;
        assert!(err(vec![(op(1), c)]).contains("GEN-2"));
        let slh = Coin { output: Output { value: 1, kind: OutputKind::P2pkSlh { pkh: [0; 32] } }, height: 0, coinbase: false };
        assert!(err(vec![(op(1), slh)]).contains("GEN-2"));
        // GEN-4: unspendable scripts are not coins.
        assert!(legacy_coin(1, vec![]).is_none());
        assert!(legacy_coin(1, vec![0x6a, 0x01, 0x00]).is_none());
        // decode_genesis_state enforces the same preconditions.
        let dup = encode_genesis_state(&vec![(op(1), coin(5)), (op(1), coin(5))]);
        assert!(decode_genesis_state(&dup).is_err());
    }

    #[test]
    fn parse_v1_dump_and_malformed_input() {
        // v1: base block hash, u64 count, then (txid, vout:u32, coin)*.
        let mut d = Vec::new();
        d.extend([9u8; 32]);
        d.extend(1u64.to_le_bytes());
        d.extend([3u8; 32]);
        d.extend(4u32.to_le_bytes());
        d.extend(varint_bytes(100 << 1));
        d.extend(varint_bytes(compress_amount(777)));
        d.extend(varint_bytes(1)); // script type 1: P2SH
        d.extend([0xcc; 20]);
        let (info, coins) = parse_dump(&d[..]).unwrap();
        assert_eq!((info.version, info.imported), (1, 1));
        assert_eq!(coins[0].0, OutPoint::new([3u8; 32], 4));
        assert_eq!(coins[0].1.output.kind, OutputKind::Legacy { script_pubkey: [vec![0xa9, 0x14], vec![0xcc; 20], vec![0x87]].concat() });
        // Truncated file.
        assert!(parse_dump(&d[..d.len() - 1]).is_err());
        // Trailing bytes.
        let mut t = d.clone();
        t.push(0);
        assert!(parse_dump(&t[..]).unwrap_err().to_string().contains("trailing"));
        // A count that the file cannot back does not pre-allocate or succeed.
        let mut huge = Vec::new();
        huge.extend([9u8; 32]);
        huge.extend(u64::MAX.to_le_bytes());
        assert!(parse_dump(&huge[..]).is_err());
        // A raw script longer than MAX_LEGACY_SCRIPT_LEN is a corrupt file.
        let mut big = Vec::new();
        big.extend([9u8; 32]);
        big.extend(1u64.to_le_bytes());
        big.extend([3u8; 32]);
        big.extend(0u32.to_le_bytes());
        big.extend(varint_bytes(0));
        big.extend(varint_bytes(compress_amount(1)));
        big.extend(varint_bytes(20_000 + 6));
        big.extend(vec![0x51; 20_000]);
        assert!(parse_dump(&big[..]).unwrap_err().to_string().contains("MAX_LEGACY_SCRIPT_LEN"));
        // VARINT overflow is an error, not a wrap.
        let mut r = Reader { r: &[0xffu8; 11][..] };
        assert!(r.varint().is_err());
    }
}
