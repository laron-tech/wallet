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

use horror::{Error, Result};
use rand::Rng;
use sha2::Digest;
use unicode_normalization::UnicodeNormalization;

use crate::bips::wordlists::Language;

use super::Seed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MnemonicError {
    InvalidMnemonicLength(usize),
    InvalidChecksum,
}

impl std::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MnemonicError::InvalidMnemonicLength(len) => {
                write!(f, "Invalid mnemonic length: {}", len)
            }
            MnemonicError::InvalidChecksum => write!(f, "Invalid checksum"),
        }
    }
}

impl std::error::Error for MnemonicError {}

/// The type of mnemonic to generate.
/// The number of words in the mnemonic is determined by the type.
/// The number of bits of entropy is also determined by the type.
/// The number of bits of entropy must be a multiple of 32 and between 128 ~ 256.
/// The number of words in the mnemonic is always a multiple of 3 and between 12 ~ 24.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicType {
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

impl MnemonicType {
    /// Create a new `MnemonicType` from the given words.
    pub fn from_word_count(words: usize) -> Result<MnemonicType> {
        match words {
            12 => Ok(MnemonicType::Words12),
            15 => Ok(MnemonicType::Words15),
            18 => Ok(MnemonicType::Words18),
            21 => Ok(MnemonicType::Words21),
            24 => Ok(MnemonicType::Words24),
            _ => Err(MnemonicError::InvalidMnemonicLength(words).into()),
        }
    }

    /// Return the number of bits in the entropy.
    pub fn entropy_bits(&self) -> usize {
        match self {
            MnemonicType::Words12 => 128,
            MnemonicType::Words15 => 160,
            MnemonicType::Words18 => 192,
            MnemonicType::Words21 => 224,
            MnemonicType::Words24 => 256,
        }
    }

    /// Return the number of words in the mnemonic.
    pub fn word_count(&self) -> usize {
        match self {
            MnemonicType::Words12 => 12,
            MnemonicType::Words15 => 15,
            MnemonicType::Words18 => 18,
            MnemonicType::Words21 => 21,
            MnemonicType::Words24 => 24,
        }
    }

    /// Return the number of bits in the checksum.
    pub fn checksum_bits(&self) -> usize {
        self.entropy_bits() / 32
    }

    /// Return the total number of bits in the mnemonic.
    pub fn total_bits(&self) -> usize {
        self.entropy_bits() + self.checksum_bits()
    }
}

/// A BIP39 mnemonic.
/// A mnemonic is a sequence of words that can be used to generate a seed.
/// It is defined in [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mnemonic {
    language: Language,
    entropy: Vec<u8>,
    phrase: String,
}

impl Mnemonic {
    /// Create a new `Mnemonic` by the given type and by the given language.
    pub fn new(ty: MnemonicType, language: Language) -> Self {
        let mut bytes = vec![0u8; ty.entropy_bits() / 8];
        rand::thread_rng().fill(&mut bytes[..]);
        Self::from_entropy_unchecked(&bytes, language)
    }

    /// Create a new `Mnemonic` from the given entropy and by the given language.
    /// The entropy must be a multiple of 32 bits.
    /// The entropy must be between 128 and 256 bits.
    pub fn from_entropy(entropy: &[u8], language: Language) -> Result<Self> {
        let _ty = MnemonicType::from_word_count(entropy.len() * 8 / 32 * 3)?;
        Ok(Self::from_entropy_unchecked(entropy, language))
    }

    fn from_entropy_unchecked(ent: &[u8], language: Language) -> Self {
        let ent = ent.to_vec();
        let wordlist = language.wordlist();

        let checksum = sha2::Sha256::digest(&ent)[0];

        let phrase = ent
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
            .map(|idx| wordlist.get(idx.into()).unwrap())
            .collect::<Vec<_>>()
            .join(" ");

        Self {
            language,
            entropy: ent,
            phrase,
        }
    }

    /// Create a new `Mnemonic` from the given phrase and by the given language.
    pub fn from_phrase(phrase: &str, language: Language) -> Result<Self> {
        let phrase = phrase.nfkd().collect::<String>();
        let ent = Self::phrase_to_entropy(&phrase, language)?;

        Ok(Self {
            language,
            entropy: ent,
            phrase,
        })
    }

    /// Validate the given phrase.
    pub fn validate_phrase(phrase: &str, language: Language) -> Result<()> {
        let phrase = phrase.nfkd().collect::<String>();
        Self::phrase_to_entropy(&phrase, language)?;
        Ok(())
    }

    fn phrase_to_entropy(phrase: &str, language: Language) -> Result<Vec<u8>> {
        let wordmap = language.wordmap();

        let bits = phrase
            .split_whitespace()
            .map(|word| wordmap.get_index(word))
            .collect::<Result<Vec<_>>>()?
            .iter()
            .flat_map(|idx| (0..11).rev().map(move |i| (idx >> i) & 1))
            .collect::<Vec<_>>();

        let ty = MnemonicType::from_word_count(bits.len() / 11)?;

        let mut ent = bits
            .chunks(8)
            .map(|chunk| chunk.iter().fold(0u8, |acc, bit| (acc << 1) | (*bit as u8)))
            .collect::<Vec<_>>();

        let checksum = ent.pop().unwrap();

        let calculated_checksum = sha2::Sha256::digest(&ent)[0];
        let expected_checksum = calculated_checksum >> (8 - ty.checksum_bits());

        if checksum != expected_checksum {
            return Err(MnemonicError::InvalidChecksum.into());
        }

        Ok(ent)
    }

    /// Return the entropy of the mnemonic.
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// Return the phrase of the mnemonic.
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// Return the language of the mnemonic.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Return the type of the mnemonic.
    pub fn mnemonic_type(&self) -> MnemonicType {
        MnemonicType::from_word_count(self.phrase.split_whitespace().count()).unwrap()
    }

    /// Return bytes representation of the mnemonic.
    pub fn to_bytes(&self) -> &[u8] {
        self.phrase().as_bytes()
    }

    /// Return the seed of the mnemonic.
    pub fn to_seed(&self, passphrase: &str) -> Seed {
        Seed::new(self, passphrase)
    }
}

impl std::fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.phrase)
    }
}

impl std::str::FromStr for Mnemonic {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_phrase(s, Language::English)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic() {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
        assert_eq!(mnemonic.entropy().len(), 16);
        assert_eq!(mnemonic.language(), Language::English);

        let mnemonic = Mnemonic::new(MnemonicType::Words15, Language::English);
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 15);
        assert_eq!(mnemonic.entropy().len(), 20);
        assert_eq!(mnemonic.language(), Language::English);

        let mnemonic = Mnemonic::new(MnemonicType::Words18, Language::English);
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 18);
        assert_eq!(mnemonic.entropy().len(), 24);
        assert_eq!(mnemonic.language(), Language::English);

        let mnemonic = Mnemonic::new(MnemonicType::Words21, Language::English);
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 21);
        assert_eq!(mnemonic.entropy().len(), 28);
        assert_eq!(mnemonic.language(), Language::English);

        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 24);
        assert_eq!(mnemonic.entropy().len(), 32);
        assert_eq!(mnemonic.language(), Language::English);
    }

    #[test]
    fn test_entropy() {
        let entropy = vec![0u8; 16];
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
        assert_eq!(mnemonic.entropy().len(), 16);
        assert_eq!(mnemonic.language(), Language::English);

        let entropy = vec![0u8; 20];
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 15);
        assert_eq!(mnemonic.entropy().len(), 20);
        assert_eq!(mnemonic.language(), Language::English);

        let entropy = vec![0u8; 24];
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 18);
        assert_eq!(mnemonic.entropy().len(), 24);
        assert_eq!(mnemonic.language(), Language::English);

        let entropy = vec![0u8; 28];
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 21);
        assert_eq!(mnemonic.entropy().len(), 28);
        assert_eq!(mnemonic.language(), Language::English);

        let entropy = vec![0u8; 32];
        let mnemonic = Mnemonic::from_entropy(&entropy, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 24);
        assert_eq!(mnemonic.entropy().len(), 32);
        assert_eq!(mnemonic.language(), Language::English);
    }

    #[test]
    fn test_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
        assert_eq!(mnemonic.entropy().len(), 16);
        assert_eq!(mnemonic.language(), Language::English);

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
        assert_eq!(mnemonic.entropy().len(), 16);
        assert_eq!(mnemonic.language(), Language::English);

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
        assert_eq!(mnemonic.entropy().len(), 16);
        assert_eq!(mnemonic.language(), Language::English);

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
        assert_eq!(mnemonic.entropy().len(), 16);
        assert_eq!(mnemonic.language(), Language::English);

        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
        assert_eq!(mnemonic.entropy().len(), 16);
        assert_eq!(mnemonic.language(), Language::English);
    }

    #[test]
    fn test_seed() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = mnemonic.to_seed("");
        assert_eq!(seed.to_bytes().len(), 64);
    }
}
