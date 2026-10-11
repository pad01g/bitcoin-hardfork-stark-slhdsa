//! SPEC §3 — canonical encoding. Little-endian fixed-width integers, Bitcoin
//! CompactSize for lengths/counts, length-prefixed byte strings. Decoding is
//! strict: non-minimal CompactSize and trailing bytes are errors (ENC-5, ENC-6).

use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    UnexpectedEof,
    NonMinimalCompactSize,
    TrailingBytes,
    InvalidTag(u8),
    InvalidValue(&'static str),
    TooLarge,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

/// Upper bound on any single collection length accepted by the decoder (ENC-7).
pub const MAX_COLLECTION_LEN: u64 = 1 << 24;

#[derive(Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn with_capacity(n: usize) -> Self {
        Self { buf: Vec::with_capacity(n) }
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    pub fn raw(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }
    /// Bitcoin CompactSize (ENC-3).
    pub fn compact(&mut self, v: u64) -> &mut Self {
        if v < 0xfd {
            self.u8(v as u8)
        } else if v <= 0xffff {
            self.u8(0xfd).u16(v as u16)
        } else if v <= 0xffff_ffff {
            self.u8(0xfe).u32(v as u32)
        } else {
            self.u8(0xff).u64(v)
        }
    }
    /// CompactSize length + bytes (ENC-4).
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.compact(v.len() as u64).raw(v)
    }
    pub fn item<T: Encode + ?Sized>(&mut self, v: &T) -> &mut Self {
        v.encode(self);
        self
    }
    pub fn vec<T: Encode>(&mut self, v: &[T]) -> &mut Self {
        self.compact(v.len() as u64);
        for x in v {
            x.encode(self);
        }
        self
    }
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::UnexpectedEof);
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DecodeError::InvalidValue("bool")),
        }
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn compact(&mut self) -> Result<u64, DecodeError> {
        let first = self.u8()?;
        let v = match first {
            0..=0xfc => first as u64,
            0xfd => {
                let v = self.u16()? as u64;
                if v < 0xfd {
                    return Err(DecodeError::NonMinimalCompactSize);
                }
                v
            }
            0xfe => {
                let v = self.u32()? as u64;
                if v <= 0xffff {
                    return Err(DecodeError::NonMinimalCompactSize);
                }
                v
            }
            0xff => {
                let v = self.u64()?;
                if v <= 0xffff_ffff {
                    return Err(DecodeError::NonMinimalCompactSize);
                }
                v
            }
        };
        Ok(v)
    }
    pub fn len(&mut self) -> Result<usize, DecodeError> {
        let v = self.compact()?;
        if v > MAX_COLLECTION_LEN || v > self.remaining() as u64 {
            // A collection cannot have more elements than there are remaining bytes
            // (every element encodes to >= 1 byte) — cheap DoS guard (ENC-7).
            return Err(DecodeError::TooLarge);
        }
        Ok(v as usize)
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let n = self.len()?;
        Ok(self.take(n)?.to_vec())
    }
    pub fn item<T: Decode>(&mut self) -> Result<T, DecodeError> {
        T::decode(self)
    }
    pub fn vec<T: Decode>(&mut self) -> Result<Vec<T>, DecodeError> {
        let n = self.len()?;
        let mut v = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            v.push(T::decode(self)?);
        }
        Ok(v)
    }
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

pub trait Encode {
    fn encode(&self, e: &mut Encoder);
    fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode(&mut e);
        e.finish()
    }
}

pub trait Decode: Sized {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError>;
    /// Decode exactly one value consuming the whole slice (ENC-6).
    fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let v = Self::decode(&mut d)?;
        d.finish()?;
        Ok(v)
    }
}

impl Encode for [u8; 32] {
    fn encode(&self, e: &mut Encoder) {
        e.raw(self);
    }
}
impl Decode for [u8; 32] {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        d.array()
    }
}
/// Byte strings are encoded explicitly with `Encoder::bytes` / `Decoder::bytes`
/// (length-prefixed); `Vec<T>` below is the generic collection encoding.
impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, e: &mut Encoder) {
        e.vec(self);
    }
}
impl<T: Decode> Decode for Vec<T> {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        d.vec()
    }
}
impl Encode for u32 {
    fn encode(&self, e: &mut Encoder) {
        e.u32(*self);
    }
}
impl Decode for u32 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        d.u32()
    }
}
impl Encode for u64 {
    fn encode(&self, e: &mut Encoder) {
        e.u64(*self);
    }
}
impl Decode for u64 {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        d.u64()
    }
}
impl<A: Encode, B: Encode> Encode for (A, B) {
    fn encode(&self, e: &mut Encoder) {
        self.0.encode(e);
        self.1.encode(e);
    }
}
impl<A: Decode, B: Decode> Decode for (A, B) {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok((A::decode(d)?, B::decode(d)?))
    }
}
