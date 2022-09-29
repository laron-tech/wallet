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

/// A seed is a secret value that is used to generate private keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seed(Vec<u8>);

impl Seed {
    /// Return the underlying byte array.
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a new Seed from a mnemonic and a passphrase.
    pub fn new(mnemonic: &Mnemonic, passphrase: &str) -> Self {
        let salt = format!("mnemonic{}", passphrase);
        let normalized = salt.nfkd().collect::<String>();

        let mut data = [0u8; 64];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(
            mnemonic.to_bytes(),
            normalized.as_bytes(),
            2048,
            &mut data,
        );

        Self(data.to_vec())
    }

    /// Return the length of the seed.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return true if the seed is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
        Ok(Self(bytes))
    }
}

impl From<Vec<u8>> for Seed {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
