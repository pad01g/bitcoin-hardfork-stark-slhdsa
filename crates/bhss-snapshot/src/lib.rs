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
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut e = bhss_primitives::Encoder::new();
    e.vec(&sorted);
    e.finish()
}

pub fn decode_genesis_state(bytes: &[u8]) -> Result<GenesisCoins> {
    let v: Vec<(OutPoint, Coin)> = Vec::from_bytes(bytes).map_err(|e| anyhow::anyhow!("genesis state decode: {e}"))?;
    Ok(v)
}

pub fn genesis_state_root(coins: &GenesisCoins) -> Hash32 {
    bhss_consensus::genesis::genesis_state_root(coins)
}

/// Write `params.json` and `genesis_state.bin` into `dir`.
pub fn write_network(dir: &std::path::Path, mut params: ChainParams, coins: &GenesisCoins) -> Result<()> {
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
    /// Bitcoin CompactSize.
    fn compact(&mut self) -> Result<u64> {
        Ok(match self.u8()? {
            n @ 0..=0xfc => n as u64,
            0xfd => self.u16()? as u64,
            0xfe => self.u32()? as u64,
            _ => self.u64()?,
        })
    }
    /// Bitcoin serialization VARINT (MSB base-128 with +1 continuation).
    fn varint(&mut self) -> Result<u64> {
        let mut n: u64 = 0;
        loop {
            let ch = self.u8()?;
            n = (n << 7) | (ch & 0x7f) as u64;
            if ch & 0x80 != 0 {
                n += 1;
            } else {
                return Ok(n);
            }
        }
    }
}

/// Core's `DecompressAmount`.
pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    x -= 1;
    let mut e = x % 10;
    x /= 10;
    let mut n = if e < 9 {
        let d = (x % 9) + 1;
        x /= 9;
        x * 10 + d
    } else {
        x + 1
    };
    while e > 0 {
        n *= 10;
        e -= 1;
    }
    n
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
            r.bytes(len)?
        }
    })
}

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
    let version;
    let base_blockhash: [u8; 32];
    if head == b"utxo\xff" {
        version = r.u16()?;
        if version != 2 {
            bail!("unsupported dumptxoutset version {version}");
        }
        let _network_magic = r.bytes(4)?;
        base_blockhash = r.bytes(32)?.try_into().unwrap();
    } else {
        // v1: no magic; the first 32 bytes are the base block hash.
        version = 1;
        head.extend(r.bytes(27)?);
        base_blockhash = head.try_into().unwrap();
    }
    let coins_count = r.u64()?;
    let mut coins = Vec::with_capacity(coins_count.min(1 << 22) as usize);
    let mut imported = 0u64;
    let mut skipped = 0u64;
    let mut read_coin = |r: &mut Reader<R>, txid: [u8; 32], vout: u32, coins: &mut GenesisCoins| -> Result<()> {
        let _code = r.varint()?; // height << 1 | coinbase (dropped, GEN-3)
        let value = decompress_amount(r.varint()?);
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
            for _ in 0..n {
                let vout = r.compact()? as u32;
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
    Ok((DumpInfo { version, base_blockhash, coins_count, imported, skipped }, coins))
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
        while n % 10 == 0 && e < 9 {
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
            assert_eq!(decompress_amount(compress_amount(v)), v);
        }
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
        d.extend(varint_bytes((100 << 1) | 0));
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
}
