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

use super::Mnemonic;
use horror::{Error, Result};
use unicode_normalization::UnicodeNormalization;

/// Seed is a 512-bit (64-byte) array used to initialize a BIP32 HD wallet.
/// It is generated from a mnemonic using the BIP39 standard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed([u8; 64]);

impl Seed {
    /// Create a new Seed from a byte array.
    pub fn new(seed: [u8; 64]) -> Self {
        Self(seed)
    }

    /// Return the underlying byte array.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a new Seed from a mnemonic and a passphrase.
    pub fn from_mnemonic(mnemonic: &Mnemonic, passphrase: &str) -> Self {
        let salt = format!("mnemonic{}", passphrase);
        let normalized = salt.nfkd().collect::<String>();

        let mut data = [0u8; 64];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(
            mnemonic.to_bytes(),
            normalized.as_bytes(),
            2048,
            &mut data,
        );

        Self(data)
    }
}

impl std::fmt::Display for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl std::str::FromStr for Seed {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        let mut seed = [0u8; 64];
        seed.copy_from_slice(&bytes);
        Ok(Self(seed))
    }
}
