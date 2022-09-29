// This file is part of the laron-wallet.
//
// Copyright (C) 2022 Ade M Ramdani
//
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! BIP32 implementation
//!
//! This module implements the BIP32 specification for hierarchical deterministic
//! wallets. It is based on the [bip32 crate](https://crates.io/crates/bip32) by iqlusion.
//! The main difference is that this implementation specializes in the use for
//! Ethereum wallets generation and derivation.

use super::{bip39::Seed, ChildNumber, DerivationPath};
use hmac::{Hmac, Mac};
use horror::Result;
use laron_crypto::{PrivateKey, PublicKey};
use ripemd::{Digest, Ripemd160};
use sha2::Sha512;

#[derive(Debug, Clone)]
pub(crate) enum ExtendedKeyError {
    DepthTooLarge,
    SeedLength,
}

impl std::fmt::Display for ExtendedKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ExtendedKeyError::DepthTooLarge => write!(f, "Depth too large"),
            ExtendedKeyError::SeedLength => write!(f, "Seed length must be 16, 32, or 64"),
        }
    }
}

impl std::error::Error for ExtendedKeyError {}

/// BIP32 implementation for deriving private and public keys
/// from a seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedKey {
    key: PrivateKey,
    public_key: PublicKey,
    parent_fingerprint: [u8; 4],
    child_number: ChildNumber,
    depth: u8,
    chain_code: [u8; 32],
}

impl ExtendedKey {
    /// Create new instance of ExtendedKey.
    pub fn new(
        key: PrivateKey,
        public_key: PublicKey,
        parent_fingerprint: [u8; 4],
        child_number: ChildNumber,
        depth: u8,
        chain_code: [u8; 32],
    ) -> Self {
        Self {
            key,
            public_key,
            parent_fingerprint,
            child_number,
            depth,
            chain_code,
        }
    }

    /// Create a new master node by the given seed.
    pub fn new_master(seed: &Seed) -> Result<Self> {
        if ![16, 32, 64].contains(&seed.len()) {
            return Err(ExtendedKeyError::SeedLength.into());
        }

        let mut hmac: Hmac<Sha512> = Hmac::new_from_slice(b"Bitcoin seed")?;
        hmac.update(seed.to_bytes());
        let bytes = hmac.finalize().into_bytes();

        let (key, chain_code) = bytes.split_at(32);
        let private_key = PrivateKey::from_bytes(key)?;
        let public_key = private_key.public_key();

        Ok(Self::new(
            private_key,
            public_key,
            [0; 4],
            ChildNumber::from(0),
            0,
            chain_code.try_into()?,
        ))
    }

    /// Derive a child node from the given child number.
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<Self> {
        let depth = self
            .depth
            .checked_add(1)
            .ok_or(ExtendedKeyError::DepthTooLarge)?;

        let mut hmac: Hmac<Sha512> = Hmac::new_from_slice(&self.chain_code)?;

        if child_number.is_hardened() {
            hmac.update(&[0]);
            hmac.update(&self.key.to_bytes());
        } else {
            hmac.update(&self.key.public_key().to_bytes());
        }

        hmac.update(&child_number.to_bytes());

        let result = hmac.finalize().into_bytes();
        let (child_key, chain_code) = result.split_at(32);

        let private_key = self.key.derive_child(child_key.try_into()?)?;
        let public_key = private_key.public_key();
        let fp = Ripemd160::digest(&self.key.public_key().to_bytes());
        let parent_fingerprint: [u8; 4] = fp[0..4].try_into()?;

        Ok(Self::new(
            private_key,
            public_key,
            parent_fingerprint,
            child_number,
            depth,
            chain_code.try_into()?,
        ))
    }

    /// Derive a child node from the given derivation path.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self> {
        let mut key = self.clone();

        for child_number in path.iter() {
            key = key.derive_child(*child_number)?;
        }

        Ok(key)
    }

    /// Get the private key.
    pub fn private_key(&self) -> &PrivateKey {
        &self.key
    }

    /// Get the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the parent fingerprint.
    pub fn parent_fingerprint(&self) -> &[u8] {
        &self.parent_fingerprint
    }

    /// Get the child number.
    pub fn child_number(&self) -> &ChildNumber {
        &self.child_number
    }

    /// Get the depth.
    pub fn depth(&self) -> u8 {
        self.depth
    }

    /// Get the chain code.
    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }
}

#[cfg(test)]
mod tests {
    use crate::bips::{bip39::Mnemonic, wordlists::Language};

    use super::*;

    #[test]
    pub fn test_master() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = mnemonic.to_seed("");
        let key = ExtendedKey::new_master(&seed).unwrap();
        assert_eq!(
            key.private_key().to_string(),
            "1837c1be8e2995ec11cda2b066151be2cfb48adf9e47b151d46adab3a21cdf67"
        );
        let child = key.derive_child(ChildNumber::from(0)).unwrap();
        assert_eq!(
            child.private_key().to_string(),
            "baa89a8bdd61c5e22b9f10601d8791c9f8fc4b2fa6df9d68d336f0eb03b06eb6"
        );
    }

    #[test]
    pub fn test_derive_path() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = mnemonic.to_seed("");
        let key = ExtendedKey::new_master(&seed).unwrap();
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let child = key.derive_path(&path).unwrap();
        assert_eq!(
            child.private_key().to_string(),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
        assert_eq!(
            child.public_key().to_string(),
            "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299"
        );
    }
}
