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

use std::fmt;

use laron_primitives::FromStr;
use rand::Rng;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use super::{error::ErrKind, Language};

#[derive(Debug, Clone)]
pub enum Type {
    /// 12 words
    Words12,
    /// 15 words
    Words15,
    /// 18 words
    Words18,
    /// 21 words
    Words21,
    /// 24 words
    Words24,
}

impl Type {
    pub fn from_words(words: usize) -> Result<Self, ErrKind> {
        match words {
            12 => Ok(Self::Words12),
            15 => Ok(Self::Words15),
            18 => Ok(Self::Words18),
            21 => Ok(Self::Words21),
            24 => Ok(Self::Words24),
            _ => Err(ErrKind::InvalidMnemonicLength(words)),
        }
    }

    pub fn total_bits(&self) -> usize {
        match self {
            Self::Words12 => 128,
            Self::Words15 => 160,
            Self::Words18 => 192,
            Self::Words21 => 224,
            Self::Words24 => 256,
        }
    }

    pub fn total_words(&self) -> usize {
        match self {
            Self::Words12 => 12,
            Self::Words15 => 15,
            Self::Words18 => 18,
            Self::Words21 => 21,
            Self::Words24 => 24,
        }
    }

    pub fn entropy_bits(&self) -> usize {
        self.total_bits() - 8 * 4
    }

    pub fn checksum_bits(&self) -> usize {
        match self {
            Self::Words12 => 4,
            Self::Words15 => 5,
            Self::Words18 => 6,
            Self::Words21 => 7,
            Self::Words24 => 8,
        }
    }
}

#[derive(Clone)]
pub struct Mnemonic {
    entropy: Vec<u8>,
    language: Language,
    phrase: String,
}

impl Mnemonic {
    /// Create a new mnemonic by the given entropy size (multiple of 32 and between 128 ~ 256), and
    /// by the prefered language.
    pub fn new(ty: Type, lang: Language) -> Result<Self, ErrKind> {
        let mut bytes = vec![0u8; ty.total_bits() as usize / 8];
        rand::thread_rng().fill(&mut bytes[..]);

        Ok(Self::from_entropy_unchecked(&bytes, lang))
    }

    /// Create a new mnemonic by the given entropy, and by the prefered language.
    /// This function will not check the entropy length.
    pub fn from_entropy(ent: &[u8], lang: Language) -> Result<Self, ErrKind> {
        if ent.len() % 4 != 0 || !(16..32).contains(&ent.len()) {
            return Err(ErrKind::InvalidEntropyLength(ent.len()));
        }

        Ok(Self::from_entropy_unchecked(ent, lang))
    }

    /// Create a new mnemonic by the given entropy, and by the prefered language.
    fn from_entropy_unchecked(ent: &[u8], lang: Language) -> Self {
        let entropy = ent.as_ref().to_vec();
        let word_list = lang.word_list();

        let checksum = Sha256::digest(&entropy)[0];

        let phrase = entropy
            .iter()
            .chain(Some(&checksum))
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1))
            .collect::<Vec<_>>()
            .chunks(11)
            .take_while(|chunk| chunk.len() == 11)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold(0u16, |acc, bit| (acc << 1) | (*bit as u16))
            })
            .map(|idx| word_list.get(idx))
            .collect::<Vec<_>>()
            .join(" ");

        Mnemonic {
            entropy,
            language: lang,
            phrase,
        }
    }

    /// Create a new mnemonic by the given phrase, and by the prefered language.
    pub fn from_phrase(phrase: &str, lang: Language) -> Result<Self, ErrKind> {
        let phrase = phrase.nfkd().collect::<String>();
        let entropy = Mnemonic::phrase_to_entropy(&phrase, lang)?;

        Ok(Self {
            entropy,
            language: lang,
            phrase,
        })
    }

    /// Validate the mnemonic phrase.
    /// This function will check the phrase length, and the checksum.
    pub fn validate(phrase: &str, lang: Language) -> Result<(), ErrKind> {
        Mnemonic::phrase_to_entropy(phrase, lang)?;

        Ok(())
    }

    /// Get the entropy from the mnemonic phrase.
    fn phrase_to_entropy(phrase: &str, lang: Language) -> Result<Vec<u8>, ErrKind> {
        let word_map = lang.word_map();

        let bits = phrase
            .split_whitespace()
            .map(|word| word_map.get_index(word))
            .collect::<Result<Vec<_>, _>>()?
            .iter()
            .flat_map(|idx| (0..11).rev().map(move |i| (idx >> i) & 1))
            .collect::<Vec<_>>();

        let mnemonic_type = Type::from_words(bits.len() / 11)?;

        let mut entropy = bits
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, bit| (acc << 1) | (*bit as u8)))
            .collect::<Vec<_>>();

        let checksum = entropy.pop().unwrap();

        let calculated_checksum = Sha256::digest(&entropy)[0];
        let expected_checksum = calculated_checksum >> (8 - mnemonic_type.checksum_bits());

        if checksum != expected_checksum {
            return Err(ErrKind::InvalidChecksum);
        }

        Ok(entropy)
    }

    /// Get the mnemonic phrase.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Get the entropy.
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// Get the language.
    pub fn language(&self) -> Language {
        self.language
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.phrase)
    }
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Mnemonic {{ phrase: \"{}\" }}", self.phrase)
    }
}

impl FromStr for Mnemonic {
    type Err = ErrKind;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Mnemonic::from_phrase(s, Language::English)
    }
}

impl From<Mnemonic> for String {
    fn from(mnemonic: Mnemonic) -> Self {
        mnemonic.phrase
    }
}

impl AsRef<str> for Mnemonic {
    fn as_ref(&self) -> &str {
        &self.phrase
    }
}

impl fmt::LowerHex for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.entropy.iter() {
            write!(f, "{:02x}", byte)?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.entropy.iter() {
            write!(f, "{:02X}", byte)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_mnemonic() {
        let mnemonic = Mnemonic::new(Type::Words12, Language::English).unwrap();
        assert_eq!(mnemonic.entropy().len(), 16);
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
    }

    #[test]
    fn test_mnemonic_from_entropy() {
        let entropy = [0u8; 16];
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        assert_eq!(mnemonic.phrase(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    }

    #[test]
    fn test_mnemonic_from_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(mnemonic.entropy(), [0u8; 16]);
    }

    #[test]
    fn test_mnemonic_validate() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        Mnemonic::validate(phrase, Language::English).unwrap();
    }
}
