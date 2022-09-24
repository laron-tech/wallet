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

use hmac::{Hmac, Mac};
use laron_crypto::crypto::SecretKey;
use sha2::Sha512;

use crate::bip39::Seed;

pub struct ExtendedKey {
    key: SecretKey,
    chain_code: Vec<u8>,
}

impl ExtendedKey {
    pub fn new(seed: &Seed) -> Result<Self, String> {
        let mut hmac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").unwrap();
        hmac.update(seed.as_bytes());
        let result = hmac.finalize().into_bytes();

        let (key, chain_code) = result.split_at(result.len() / 2);
        let key = SecretKey::from_slice(key).map_err(|_| "Invalid key")?;

        Ok(Self {
            key,
            chain_code: chain_code.to_vec(),
        })
    }

    pub fn derive(&self, index: u32) -> Result<Self, String> {
        let mut hmac = Hmac::<Sha512>::new_from_slice(&self.chain_code).unwrap();
        hmac.update(&self.key.to_bytes());
        hmac.update(&index.to_be_bytes());
        let result = hmac.finalize().into_bytes();

        let (key, chain_code) = result.split_at(result.len() / 2);
        let key = SecretKey::from_slice(key).map_err(|_| "Invalid key")?;

        Ok(Self {
            key,
            chain_code: chain_code.to_vec(),
        })
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.key
    }
}

#[cfg(test)]
mod test {
    use laron_crypto::common::Address;

    use crate::bip39::{Language, Mnemonic};

    use super::*;

    #[test]
    fn test() {
        let mnemonic = Mnemonic::from_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        let extended_key = ExtendedKey::new(&seed).unwrap();
        let extended_key = extended_key.derive(0).unwrap();
        let secret_key = extended_key.secret_key();
        let public_key = secret_key.public_key().unwrap();
        let address = Address::from_public_key(public_key);
        println!("{}", address.to_hex());
        assert_eq!(true, false);
    }
}
