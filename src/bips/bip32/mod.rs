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

use super::{bip39::Seed, ChildNumber, DerivationPath};
use hmac::{Hmac, Mac};
use horror::Result;
use laron_crypto::PrivateKey;
use ripemd::{Digest, Ripemd160};
use sha2::Sha512;

#[derive(Debug, Clone)]
pub(crate) enum ExtendedKeyError {
    DepthTooLarge,
}

impl std::fmt::Display for ExtendedKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ExtendedKeyError::DepthTooLarge => write!(f, "Depth too large"),
        }
    }
}

impl std::error::Error for ExtendedKeyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedKey {
    key: PrivateKey,
    parent_fingerprint: [u8; 4],
    child_number: ChildNumber,
    depth: u8,
    chain_code: [u8; 32],
    version: u32,
}

impl ExtendedKey {
    pub const MAX_DEPTH: u8 = u8::MAX;

    pub fn new(seed: &Seed) -> Result<Self> {
        let mut hmac: Hmac<Sha512> = Hmac::new_from_slice(b"Bitcoin seed")?;
        hmac.update(seed.to_bytes());
        let bytes = hmac.finalize().into_bytes();

        let (key, chain_code) = bytes.split_at(32);
        let private_key = PrivateKey::from_bytes(key)?;

        Ok(Self {
            key: private_key,
            parent_fingerprint: [0; 4],
            child_number: ChildNumber::from(0),
            depth: 0,
            chain_code: chain_code.try_into()?,
            version: 0,
        })
    }

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
        let parent_fingerprint = Ripemd160::digest(&self.key.public_key().to_bytes());
        let parent_fingerprint: [u8; 4] = parent_fingerprint[0..4].try_into()?;

        Ok(Self {
            key: private_key,
            parent_fingerprint,
            child_number,
            depth,
            chain_code: chain_code.try_into()?,
            version: 0,
        })
    }

    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self> {
        let mut key = self.clone();

        for child_number in path.iter() {
            key = key.derive_child(*child_number)?;
        }

        Ok(key)
    }

    pub fn key(&self) -> &PrivateKey {
        &self.key
    }

    pub fn parent_fingerprint(&self) -> &[u8; 4] {
        &self.parent_fingerprint
    }

    pub fn child_number(&self) -> &ChildNumber {
        &self.child_number
    }

    pub fn depth(&self) -> u8 {
        self.depth
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn version(&self) -> u32 {
        self.version
    }
}
