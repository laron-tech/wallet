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

use horror::Result;

/// ChildNumber represents a child number in a BIP32 derivation path.
/// Child numbers are hardened if the most significant bit is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildNumber(u32);

impl ChildNumber {
    /// Creates a new hardened ChildNumber.
    pub fn hardened(n: u32) -> Self {
        Self(n | 0x80000000)
    }

    /// Creates a new normal ChildNumber.
    pub fn normal(n: u32) -> Self {
        Self(n)
    }

    /// Returns true if the ChildNumber is hardened.
    pub fn is_hardened(&self) -> bool {
        self.0 & 0x80000000 != 0
    }

    /// Returns the index of the ChildNumber.
    pub fn index(&self) -> u32 {
        self.0 & 0x7FFFFFFF
    }

    /// Returns the bytes of the ChildNumber.
    pub fn to_bytes(&self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
}

impl From<u32> for ChildNumber {
    fn from(n: u32) -> Self {
        Self::normal(n)
    }
}

impl From<ChildNumber> for u32 {
    fn from(n: ChildNumber) -> Self {
        n.0
    }
}

/// Error returned when parsing a BIP32 derivation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The path is empty.
    Empty,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Empty => write!(f, "empty path"),
        }
    }
}

impl std::error::Error for Error {}

/// DerivationPath represents the computer friendly version of a hierarchical
/// deterministic wallet account derivation path.
///
/// The [BIP-32 spec](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
/// defines derivation paths to be of the form:
///
///   m / purpose' / coin_type' / account' / change / address_index
///
/// The [BIP-44 spec](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
/// defines that the `purpose` be 44' (or 0x8000002C) for crypto currencies, and
/// [SLIP-44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) assigns
/// the `coin_type` 60' (or 0x8000003C) to Ethereum.
///
/// The root path for Ethereum is m/44'/60'/0'/0 according to the specification
/// from <https://github.com/ethereum/EIPs/issues/84>, albeit it's not set in stone
/// yet whether accounts should increment the last component or the children of
/// that. We will go with the simpler approach of incrementing the last component.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationPath(Vec<ChildNumber>);

impl DerivationPath {
    /// Parses a derivation path from a string.
    pub fn parse(path: &str) -> Result<Self> {
        let path = path.split('/');
        let mut result = Vec::new();

        if path.clone().count() == 0 {
            return Err(Error::Empty.into());
        }

        for component in path {
            if component == "m" {
                continue;
            }
            let hardened = component.ends_with('\'');
            let index = component.trim_end_matches('\'').parse::<u32>()?;

            if hardened {
                result.push(ChildNumber::hardened(index));
            } else {
                result.push(ChildNumber::normal(index));
            }
        }

        Ok(Self(result))
    }

    /// Returns the derivation path as a string.
    pub fn string(&self) -> String {
        let mut result = String::new();

        for (i, component) in self.0.iter().enumerate() {
            if i == 0 {
                result.push_str("m/");
            } else {
                result.push('/');
            }

            result.push_str(&component.index().to_string());

            if component.is_hardened() {
                result.push('\'');
            }
        }

        result
    }

    /// Returns the derivation path as a byte vector.
    pub fn bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();

        for component in self.0.iter() {
            result.extend_from_slice(&component.to_bytes());
        }

        result
    }

    /// Returns the iterator over the components of the derivation path.
    pub fn iter(&self) -> std::slice::Iter<ChildNumber> {
        self.0.iter()
    }
}

impl Default for DerivationPath {
    fn default() -> Self {
        Self::parse("m/44'/60'/0'/0").unwrap()
    }
}

impl std::fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let path = DerivationPath::parse("m/44'/60'/0'/0").unwrap();
        assert_eq!(path.string(), "m/44'/60'/0'/0");
    }
}
