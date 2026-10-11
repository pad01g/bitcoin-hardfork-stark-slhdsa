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
    if kind.slh_condition().is_none() {
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
