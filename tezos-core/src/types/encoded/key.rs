#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    internal::{
        coder::{EncodedBytesCoder, PublicKeyBytesCoder},
        crypto::blake2b,
    },
    types::encoded::{
        Bls12_381PublicKey, Bls12_381PublicKeyHash, Bls12_381SecretKey, Ed25519PublicKey,
        Ed25519PublicKeyHash, Ed25519SecretKey, Encoded, ImplicitAddress, MetaEncoded,
        P256PublicKey, P256PublicKeyHash, P256SecretKey, Secp256K1PublicKey,
        Secp256K1PublicKeyHash, Secp256K1SecretKey,
    },
    Error, Result,
};

/// Group of base58 encoded cryptographic keys, either secret or public.
///
/// See:
/// - [SecretKey]
/// - [PublicKey]
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", untagged)
)]
pub enum Key {
    Secret(SecretKey),
    Public(PublicKey),
}

impl Encoded for Key {
    type Coder = EncodedBytesCoder;

    fn value(&self) -> &str {
        match self {
            Self::Secret(value) => value.value(),
            Self::Public(value) => value.value(),
        }
    }

    fn meta(&self) -> &'static MetaEncoded {
        match self {
            Self::Secret(value) => value.meta(),
            Self::Public(value) => value.meta(),
        }
    }

    fn new(value: String) -> Result<Self> {
        if SecretKey::is_valid_base58(&value) {
            return Ok(Self::Secret(SecretKey::new(value)?));
        }
        if PublicKey::is_valid_base58(&value) {
            return Ok(Self::Public(PublicKey::new(value)?));
        }
        Err(Error::InvalidBase58EncodedData { description: value })
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Key::Secret(value) => value.to_bytes(),
            Key::Public(value) => value.to_bytes(),
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if SecretKey::is_valid_bytes(bytes) {
            return Ok(Self::Secret(SecretKey::from_bytes(bytes)?));
        }
        if PublicKey::is_valid_bytes(bytes) {
            return Ok(Self::Public(PublicKey::from_bytes(bytes)?));
        }
        Err(Error::InvalidBytes)
    }
}

impl From<Key> for String {
    fn from(value: Key) -> Self {
        match value {
            Key::Secret(value) => value.into(),
            Key::Public(value) => value.into(),
        }
    }
}

impl TryFrom<&Vec<u8>> for Key {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Self::from_bytes(value)
    }
}

impl TryFrom<String> for Key {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        Key::new(value)
    }
}

impl TryFrom<&str> for Key {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        Key::new(value.to_string())
    }
}

impl TryFrom<&Key> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &Key) -> Result<Self> {
        value.to_bytes()
    }
}

/// Group of base58 encoded secret keys.
///
/// See:
/// - [Ed25519SecretKey]
/// - [Secp256K1SecretKey]
/// - [P256SecretKey]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", untagged)
)]
pub enum SecretKey {
    Ed25519(Ed25519SecretKey),
    Secp256K1(Secp256K1SecretKey),
    P256(P256SecretKey),
    Bls12_381(Bls12_381SecretKey),
}

impl SecretKey {
    pub fn is_valid_base58(value: &str) -> bool {
        Ed25519SecretKey::is_valid_base58(value)
            || Secp256K1SecretKey::is_valid_base58(value)
            || P256SecretKey::is_valid_base58(value)
            || Bls12_381SecretKey::is_valid_base58(value)
    }

    pub fn is_valid_bytes(value: &[u8]) -> bool {
        Ed25519SecretKey::is_valid_bytes(value)
            || Secp256K1SecretKey::is_valid_bytes(value)
            || P256SecretKey::is_valid_bytes(value)
            || Bls12_381SecretKey::is_valid_bytes(value)
    }
}

impl Encoded for SecretKey {
    type Coder = EncodedBytesCoder;

    fn value(&self) -> &str {
        match self {
            Self::Ed25519(value) => value.value(),
            Self::Secp256K1(value) => value.value(),
            Self::P256(value) => value.value(),
            Self::Bls12_381(value) => value.value(),
        }
    }

    fn meta(&self) -> &'static MetaEncoded {
        match self {
            Self::Ed25519(value) => value.meta(),
            Self::Secp256K1(value) => value.meta(),
            Self::P256(value) => value.meta(),
            Self::Bls12_381(value) => value.meta(),
        }
    }

    fn new(value: String) -> Result<Self> {
        if Ed25519SecretKey::is_valid_base58(&value) {
            return Ok(Self::Ed25519(Ed25519SecretKey::new(value)?));
        }
        if Secp256K1SecretKey::is_valid_base58(&value) {
            return Ok(Self::Secp256K1(Secp256K1SecretKey::new(value)?));
        }
        if P256SecretKey::is_valid_base58(&value) {
            return Ok(Self::P256(P256SecretKey::new(value)?));
        }
        if Bls12_381SecretKey::is_valid_base58(&value) {
            return Ok(Self::Bls12_381(Bls12_381SecretKey::new(value)?));
        }
        Err(Error::InvalidBase58EncodedData { description: value })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if Ed25519SecretKey::is_valid_bytes(bytes) {
            return Ok(Self::Ed25519(Ed25519SecretKey::from_bytes(bytes)?));
        }
        if Secp256K1SecretKey::is_valid_bytes(bytes) {
            return Ok(Self::Secp256K1(Secp256K1SecretKey::from_bytes(bytes)?));
        }
        if P256SecretKey::is_valid_bytes(bytes) {
            return Ok(Self::P256(P256SecretKey::from_bytes(bytes)?));
        }
        if Bls12_381SecretKey::is_valid_bytes(bytes) {
            return Ok(Self::Bls12_381(Bls12_381SecretKey::from_bytes(bytes)?));
        }
        Err(Error::InvalidBytes)
    }
}

impl From<SecretKey> for String {
    fn from(value: SecretKey) -> Self {
        match value {
            SecretKey::Ed25519(value) => value.into(),
            SecretKey::Secp256K1(value) => value.into(),
            SecretKey::P256(value) => value.into(),
            SecretKey::Bls12_381(value) => value.into(),
        }
    }
}

impl TryFrom<&Vec<u8>> for SecretKey {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Self::from_bytes(value)
    }
}

impl TryFrom<String> for SecretKey {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        SecretKey::new(value)
    }
}

impl TryFrom<&str> for SecretKey {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        SecretKey::new(value.to_string())
    }
}

impl TryFrom<&SecretKey> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &SecretKey) -> Result<Self> {
        value.to_bytes()
    }
}

impl From<Ed25519SecretKey> for SecretKey {
    fn from(value: Ed25519SecretKey) -> Self {
        Self::Ed25519(value)
    }
}

impl From<Secp256K1SecretKey> for SecretKey {
    fn from(value: Secp256K1SecretKey) -> Self {
        Self::Secp256K1(value)
    }
}

impl From<P256SecretKey> for SecretKey {
    fn from(value: P256SecretKey) -> Self {
        Self::P256(value)
    }
}

impl From<Bls12_381SecretKey> for SecretKey {
    fn from(value: Bls12_381SecretKey) -> Self {
        Self::Bls12_381(value)
    }
}

/// Group of base58 encoded public keys.
///
/// See:
/// - [Ed25519PublicKey]
/// - [Secp256K1PublicKey]
/// - [P256PublicKey]
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(try_from = "String", untagged)
)]
pub enum PublicKey {
    Ed25519(Ed25519PublicKey),
    Secp256K1(Secp256K1PublicKey),
    P256(P256PublicKey),
    Bls12_381(Bls12_381PublicKey),
}

impl PublicKey {
    pub fn is_valid_base58(value: &str) -> bool {
        Ed25519PublicKey::is_valid_base58(value)
            || Secp256K1PublicKey::is_valid_base58(value)
            || P256PublicKey::is_valid_base58(value)
            || Bls12_381PublicKey::is_valid_base58(value)
    }

    pub fn is_valid_bytes(value: &[u8]) -> bool {
        Ed25519PublicKey::is_valid_bytes(value)
            || Secp256K1PublicKey::is_valid_bytes(value)
            || P256PublicKey::is_valid_bytes(value)
            || Bls12_381PublicKey::is_valid_bytes(value)
    }

    /// Base58 encoded address
    pub fn bs58_address(&self) -> Result<String> {
        self.address().map(|address| address.into_string())
    }

    fn address(&self) -> Result<ImplicitAddress> {
        fn address_of<T: Encoded>(v: &[u8]) -> Result<T> {
            blake2b(v, 20).map(|hash| T::from_bytes(hash.as_slice()))?
        }

        let address = match self {
            Self::Ed25519(value) => {
                ImplicitAddress::from(address_of::<Ed25519PublicKeyHash>(&value.to_bytes()?)?)
            }
            Self::Secp256K1(value) => {
                ImplicitAddress::from(address_of::<Secp256K1PublicKeyHash>(&value.to_bytes()?)?)
            }
            Self::P256(value) => {
                ImplicitAddress::from(address_of::<P256PublicKeyHash>(&value.to_bytes()?)?)
            }
            Self::Bls12_381(value) => {
                ImplicitAddress::from(address_of::<Bls12_381PublicKeyHash>(&value.to_bytes()?)?)
            }
        };

        Ok(address)
    }
}

impl Encoded for PublicKey {
    type Coder = PublicKeyBytesCoder;

    fn value(&self) -> &str {
        match self {
            Self::Ed25519(value) => value.value(),
            Self::Secp256K1(value) => value.value(),
            Self::P256(value) => value.value(),
            Self::Bls12_381(value) => value.value(),
        }
    }

    fn meta(&self) -> &'static MetaEncoded {
        match self {
            Self::Ed25519(value) => value.meta(),
            Self::Secp256K1(value) => value.meta(),
            Self::P256(value) => value.meta(),
            Self::Bls12_381(value) => value.meta(),
        }
    }

    fn new(value: String) -> Result<Self> {
        if Ed25519PublicKey::is_valid_base58(&value) {
            return Ok(Self::Ed25519(Ed25519PublicKey::new(value)?));
        }
        if Secp256K1PublicKey::is_valid_base58(&value) {
            return Ok(Self::Secp256K1(Secp256K1PublicKey::new(value)?));
        }
        if P256PublicKey::is_valid_base58(&value) {
            return Ok(Self::P256(P256PublicKey::new(value)?));
        }
        if Bls12_381PublicKey::is_valid_base58(&value) {
            return Ok(Self::Bls12_381(Bls12_381PublicKey::new(value)?));
        }
        Err(Error::InvalidBase58EncodedData { description: value })
    }
}

impl From<PublicKey> for String {
    fn from(value: PublicKey) -> Self {
        match value {
            PublicKey::Ed25519(value) => value.into(),
            PublicKey::Secp256K1(value) => value.into(),
            PublicKey::P256(value) => value.into(),
            PublicKey::Bls12_381(value) => value.into(),
        }
    }
}

impl TryFrom<&Vec<u8>> for PublicKey {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self> {
        Self::from_bytes(value)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = Error;

    fn try_from(value: String) -> Result<Self> {
        PublicKey::new(value)
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        PublicKey::new(value.to_string())
    }
}

impl TryFrom<&PublicKey> for Vec<u8> {
    type Error = Error;

    fn try_from(value: &PublicKey) -> Result<Self> {
        value.to_bytes()
    }
}

impl From<Ed25519PublicKey> for PublicKey {
    fn from(value: Ed25519PublicKey) -> Self {
        Self::Ed25519(value)
    }
}

impl From<Secp256K1PublicKey> for PublicKey {
    fn from(value: Secp256K1PublicKey) -> Self {
        Self::Secp256K1(value)
    }
}

impl From<P256PublicKey> for PublicKey {
    fn from(value: P256PublicKey) -> Self {
        Self::P256(value)
    }
}

impl From<Bls12_381PublicKey> for PublicKey {
    fn from(value: Bls12_381PublicKey) -> Self {
        Self::Bls12_381(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_edpk_key_1() -> Result<()> {
        let key: Key = "edpkuF5y5V7NNH5xKMCKHHqVDzq6YuUXiPT3FFjA9CGnht6xCgziTe".try_into()?;
        if let Key::Public(key) = key {
            assert_eq!(
                key.value(),
                "edpkuF5y5V7NNH5xKMCKHHqVDzq6YuUXiPT3FFjA9CGnht6xCgziTe"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_edpk_key_2() -> Result<()> {
        let key: Key = "edskRhKTQkgxb7CNTr31rzy3xdkyKaYX9hySAnZYJTPmUzPB7WU4NL7C8pmtQDgRqQ4jDw4Ugh6Y1UW5nvo7UYrRbyhVYK1YuR".try_into()?;
        if let Key::Secret(key) = key {
            assert_eq!(
                key.value(),
                "edskRhKTQkgxb7CNTr31rzy3xdkyKaYX9hySAnZYJTPmUzPB7WU4NL7C8pmtQDgRqQ4jDw4Ugh6Y1UW5nvo7UYrRbyhVYK1YuR"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_edpk_public_key() -> Result<()> {
        let key: PublicKey = "edpkuF5y5V7NNH5xKMCKHHqVDzq6YuUXiPT3FFjA9CGnht6xCgziTe".try_into()?;
        if let PublicKey::Ed25519(key) = key {
            assert_eq!(
                key.value(),
                "edpkuF5y5V7NNH5xKMCKHHqVDzq6YuUXiPT3FFjA9CGnht6xCgziTe"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_edpk_to_tz1() {
        let key: PublicKey = "edpkuF5y5V7NNH5xKMCKHHqVDzq6YuUXiPT3FFjA9CGnht6xCgziTe"
            .try_into()
            .unwrap();
        let address = key.bs58_address().unwrap();
        assert_eq!(address, "tz1VZFmv9dJj7QFs8nv5JTjJiYJxVQXqmDMv".to_string())
    }

    #[test]
    fn test_edpk_secret_key() -> Result<()> {
        let key: SecretKey = "edskRhKTQkgxb7CNTr31rzy3xdkyKaYX9hySAnZYJTPmUzPB7WU4NL7C8pmtQDgRqQ4jDw4Ugh6Y1UW5nvo7UYrRbyhVYK1YuR".try_into()?;
        if let SecretKey::Ed25519(key) = key {
            assert_eq!(
                key.value(),
                "edskRhKTQkgxb7CNTr31rzy3xdkyKaYX9hySAnZYJTPmUzPB7WU4NL7C8pmtQDgRqQ4jDw4Ugh6Y1UW5nvo7UYrRbyhVYK1YuR"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_secp_256_k1_key_1() -> Result<()> {
        let key: Key = "sppkDN74FpFyXiHUe7MZS7rwDzzwb2esc21355LEcSExN67KdNnAfqA".try_into()?;
        if let Key::Public(key) = key {
            assert_eq!(
                key.value(),
                "sppkDN74FpFyXiHUe7MZS7rwDzzwb2esc21355LEcSExN67KdNnAfqA"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_secp_256_k1_key_2() -> Result<()> {
        let key: Key = "spsk2WUw2TFXQq2CsrNhB7EfFzdhMyNvGoYgD4uGQ6e17MgoRDv1co".try_into()?;
        if let Key::Secret(key) = key {
            assert_eq!(
                key.value(),
                "spsk2WUw2TFXQq2CsrNhB7EfFzdhMyNvGoYgD4uGQ6e17MgoRDv1co"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_secp_256_k1_public_key() -> Result<()> {
        let key: PublicKey =
            "sppkDN74FpFyXiHUe7MZS7rwDzzwb2esc21355LEcSExN67KdNnAfqA".try_into()?;
        if let PublicKey::Secp256K1(key) = key {
            assert_eq!(
                key.value(),
                "sppkDN74FpFyXiHUe7MZS7rwDzzwb2esc21355LEcSExN67KdNnAfqA"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_sppk_to_tz2() {
        let key: PublicKey = "sppkDN74FpFyXiHUe7MZS7rwDzzwb2esc21355LEcSExN67KdNnAfqA"
            .try_into()
            .unwrap();
        let address = key.bs58_address().unwrap();
        assert_eq!(address, "tz2WHHyhmspQDmKzAZmDmUyqkhcS3BA5EiuU".to_string())
    }

    #[test]
    fn test_secp_256_k1_secret_key() -> Result<()> {
        let key: SecretKey = "spsk2WUw2TFXQq2CsrNhB7EfFzdhMyNvGoYgD4uGQ6e17MgoRDv1co".try_into()?;
        if let SecretKey::Secp256K1(key) = key {
            assert_eq!(
                key.value(),
                "spsk2WUw2TFXQq2CsrNhB7EfFzdhMyNvGoYgD4uGQ6e17MgoRDv1co"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_p256_key_1() -> Result<()> {
        let key: Key = "p2pkDkL6thzTwyPjpmMotSqeKy1MAftLrseqTALwBhHwUtXRmFV983f".try_into()?;
        if let Key::Public(key) = key {
            assert_eq!(
                key.value(),
                "p2pkDkL6thzTwyPjpmMotSqeKy1MAftLrseqTALwBhHwUtXRmFV983f"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_p256_key_2() -> Result<()> {
        let key: Key = "p2sk2Xoduh8dx6B3smV81NMV25cYpZJj7yYWMRARedzyJae8SB9auw".try_into()?;
        if let Key::Secret(key) = key {
            assert_eq!(
                key.value(),
                "p2sk2Xoduh8dx6B3smV81NMV25cYpZJj7yYWMRARedzyJae8SB9auw"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_p256_public_key() -> Result<()> {
        let key: PublicKey =
            "p2pkDkL6thzTwyPjpmMotSqeKy1MAftLrseqTALwBhHwUtXRmFV983f".try_into()?;
        if let PublicKey::P256(key) = key {
            assert_eq!(
                key.value(),
                "p2pkDkL6thzTwyPjpmMotSqeKy1MAftLrseqTALwBhHwUtXRmFV983f"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_p2pk_to_tz2() {
        let key: PublicKey = "p2pkDkL6thzTwyPjpmMotSqeKy1MAftLrseqTALwBhHwUtXRmFV983f"
            .try_into()
            .unwrap();
        let address = key.bs58_address().unwrap();
        assert_eq!(address, "tz3c6Z7Vaz3jDfpKLof6PSJsHsUDYjBbQpbn".to_string())
    }

    #[test]
    fn test_p256_secret_key() -> Result<()> {
        let key: SecretKey = "p2sk2Xoduh8dx6B3smV81NMV25cYpZJj7yYWMRARedzyJae8SB9auw".try_into()?;
        if let SecretKey::P256(key) = key {
            assert_eq!(
                key.value(),
                "p2sk2Xoduh8dx6B3smV81NMV25cYpZJj7yYWMRARedzyJae8SB9auw"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }
    #[test]
    fn test_bls12_381_key_public() -> Result<()> {
        let key: Key =
            "BLpk1EAJYh9xuwXX2PbevaNLNwRWGcTJ5q6corWkUqJtRJXhSCtAAmSUcqs4BZTqUaUxhtxvMGHZ"
                .try_into()?;
        if let Key::Public(pk) = key {
            assert_eq!(
                pk.value(),
                "BLpk1EAJYh9xuwXX2PbevaNLNwRWGcTJ5q6corWkUqJtRJXhSCtAAmSUcqs4BZTqUaUxhtxvMGHZ"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_bls12_381_key_secret() -> Result<()> {
        // BLsk bytes = 1..=32 per your encoded.rs entry
        let key: Key = "BLsk1WMaoyRDXHuLDViHoExYpeCE52AH9y3n2YZUrF1yYPqgkMxLQB".try_into()?;
        if let Key::Secret(sk) = key {
            assert_eq!(
                sk.value(),
                "BLsk1WMaoyRDXHuLDViHoExYpeCE52AH9y3n2YZUrF1yYPqgkMxLQB"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_blpk_public_key_variant() -> Result<()> {
        let key: PublicKey =
            "BLpk1EAJYh9xuwXX2PbevaNLNwRWGcTJ5q6corWkUqJtRJXhSCtAAmSUcqs4BZTqUaUxhtxvMGHZ"
                .try_into()?;
        if let PublicKey::Bls12_381(pk) = key {
            assert_eq!(
                pk.value(),
                "BLpk1EAJYh9xuwXX2PbevaNLNwRWGcTJ5q6corWkUqJtRJXhSCtAAmSUcqs4BZTqUaUxhtxvMGHZ"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }

    #[test]
    fn test_blpk_to_tz4() {
        // Public key (raw BLpk bytes = 1..=48, as in encoded.rs)
        let key: PublicKey =
            "BLpk1EAJYh9xuwXX2PbevaNLNwRWGcTJ5q6corWkUqJtRJXhSCtAAmSUcqs4BZTqUaUxhtxvMGHZ"
                .try_into()
                .unwrap();

        // What bs58_address() returns
        let address = key.bs58_address().unwrap();

        // Expected tz4 = blake2b-160 over RAW BLpk bytes (NOT tagged),
        // then Base58Check with the tz4 meta (bytes_prefix [6,161,166]).
        let blpk: Bls12_381PublicKey =
            "BLpk1EAJYh9xuwXX2PbevaNLNwRWGcTJ5q6corWkUqJtRJXhSCtAAmSUcqs4BZTqUaUxhtxvMGHZ"
                .try_into()
                .unwrap();
        let raw = blpk.to_bytes().unwrap(); // 48 bytes
        let h160 = blake2b(&raw, 20).unwrap();
        let expected = Bls12_381PublicKeyHash::from_bytes(&h160)
            .unwrap()
            .into_string();

        assert_eq!(address, expected);
        assert!(address.starts_with("tz4"));
        assert_eq!(address.len(), 36);
    }

    #[test]
    fn test_bls12_381_secret_key_variant() -> Result<()> {
        let key: SecretKey = "BLsk1WMaoyRDXHuLDViHoExYpeCE52AH9y3n2YZUrF1yYPqgkMxLQB".try_into()?;
        if let SecretKey::Bls12_381(sk) = key {
            assert_eq!(
                sk.value(),
                "BLsk1WMaoyRDXHuLDViHoExYpeCE52AH9y3n2YZUrF1yYPqgkMxLQB"
            );
            return Ok(());
        }
        Err(Error::InvalidConversion)
    }
}
