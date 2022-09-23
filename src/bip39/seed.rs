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

use core::fmt;

use unicode_normalization::UnicodeNormalization;

use super::Mnemonic;

#[derive(Clone)]
pub struct Seed {
    data: Vec<u8>,
}

impl Seed {
    /// Create a new seed from mnemonic.
    pub fn new(mnemonic: &Mnemonic, password: &str) -> Self {
        let salt = format!("mnemonic{}", password);
        let normalized = salt.nfkd().collect::<String>();
        
        let mut data = [0u8; 64];
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha512>>(mnemonic.phrase().as_bytes(), normalized.as_bytes(), 2048, &mut data);

        Self { data: data.to_vec() }
    }

    /// Return Seed as bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#X}", self)
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

impl fmt::LowerHex for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }

        for byte in &self.data {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            f.write_str("0x")?;
        }

        for byte in self.data.iter() {
            write!(f, "{:02X}", byte)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::bip39::Language;

    use super::*;

    #[test]
    fn test_seed() {
        let ent = &[24, 203, 201, 245, 141, 173, 127, 98, 227, 170, 29, 214, 112, 235, 5, 57];
        let mnemonic = Mnemonic::from_entropy(ent, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "password");
        assert_eq!(format!("{:x}", seed), "af319d014e8ddfe16734f5bb9c2aa563666c7d24a35cd50a2239dc6a8eeaacfcc81996c057a5b2f71736d01084f26916cdd76f63f01ea8a3245fdc8cbf67bd8b");
    }
}
