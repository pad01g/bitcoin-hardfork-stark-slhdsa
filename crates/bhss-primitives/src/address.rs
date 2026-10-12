//! ADDR-1: an address is `bech32m(hrp = params.name, enc(OutputKind))` for
//! the spendable SLH kinds only (P2pkSlh, MultisigSlh, Timelock).

use alloc::string::String;

use bech32::{Bech32m, Hrp};

use crate::encoding::{Decode, Encode};
use crate::types::OutputKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    NotAddressable,
    Bech32,
    WrongNetwork,
    Payload,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddressError {}

pub fn encode(hrp: &str, kind: &OutputKind) -> Result<String, AddressError> {
    if kind.slh_condition().is_none() || !kind.is_well_formed() {
        return Err(AddressError::NotAddressable);
    }
    let hrp = Hrp::parse(hrp).map_err(|_| AddressError::Bech32)?;
    bech32::encode::<Bech32m>(hrp, &kind.to_bytes()).map_err(|_| AddressError::Bech32)
}

pub fn decode(expected_hrp: &str, addr: &str) -> Result<OutputKind, AddressError> {
    let (hrp, data) = bech32::decode(addr).map_err(|_| AddressError::Bech32)?;
    if hrp.as_str() != expected_hrp {
        return Err(AddressError::WrongNetwork);
    }
    let kind = OutputKind::from_bytes(&data).map_err(|_| AddressError::Payload)?;
    if kind.slh_condition().is_none() || !kind.is_well_formed() {
        return Err(AddressError::NotAddressable);
    }
    Ok(kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;

    #[test]
    fn roundtrip_and_rejections() {
        let p2pk = OutputKind::P2pkSlh { pkh: [7u8; 32] };
        let ms = OutputKind::MultisigSlh { k: 2, pkhs: vec![[1u8; 32], [2u8; 32], [3u8; 32]] };
        let tl = OutputKind::Timelock { abs_height: 10, rel_blocks: 0, inner: Box::new(ms.clone()) };
        for kind in [&p2pk, &ms, &tl] {
            let a = encode("bhrt", kind).unwrap();
            assert!(a.starts_with("bhrt1"));
            assert_eq!(&decode("bhrt", &a).unwrap(), kind);
            assert_eq!(decode("bhsn", &a), Err(AddressError::WrongNetwork));
        }
        // Only spendable, well-formed SLH kinds have addresses (ADDR-1).
        assert_eq!(encode("bhrt", &OutputKind::Data { data: vec![1] }), Err(AddressError::NotAddressable));
        assert_eq!(encode("bhrt", &OutputKind::Legacy { script_pubkey: vec![0x51] }), Err(AddressError::NotAddressable));
        let dup = OutputKind::MultisigSlh { k: 1, pkhs: vec![[1u8; 32], [1u8; 32]] };
        assert_eq!(encode("bhrt", &dup), Err(AddressError::NotAddressable));
        // A corrupted character breaks the checksum.
        let mut a = encode("bhrt", &p2pk).unwrap();
        let last = if a.ends_with('q') { 'p' } else { 'q' };
        a.pop();
        a.push(last);
        assert_eq!(decode("bhrt", &a), Err(AddressError::Bech32));
    }
}
