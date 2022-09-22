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

use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

mod words;

/// WordList is a list of words in a particular language.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordList {
    /// The words in the list.
    words: &'static [&'static str],
    /// The language of the list.
    language: Language,
}

fn wsplit(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

/// Language is a language that a word list can be in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Language {
    /// English
    English,
    /// Simplified Chinese
    SimplifiedChinese,
    /// Traditional Chinese
    TraditionalChinese,
    /// French
    French,
    /// Italian
    Italian,
    /// Japanese
    Japanese,
    /// Korean
    Korean,
    /// Spanish
    Spanish,
}

/// BIP39 implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BIP39(WordList);

//--------- WordList impls
impl WordList {
    /// create a new WordList by the given language.
    pub fn new(language: Language) -> Self {
        let words_list = match language {
            Language::English => wsplit(words::ENGLISH),
            Language::SimplifiedChinese => wsplit(words::CHINESE_SIMPLIFIED),
            Language::TraditionalChinese => wsplit(words::CHINESE_TRADITIONAL),
            Language::French => wsplit(words::FRENCH),
            Language::Italian => wsplit(words::ITALIAN),
            Language::Japanese => wsplit(words::JAPANESE),
            Language::Korean => wsplit(words::KOREAN),
            Language::Spanish => wsplit(words::SPANISH),
        };

        WordList {
            words: Box::leak(words_list.into_boxed_slice()),
            language,
        }
    }

    /// get the word by the given index.
    pub fn get(&self, index: usize) -> Option<&str> {
        self.words.get(index).copied()
    }

    /// get the index of the given word.
    pub fn index_of(&self, word: &str) -> Option<usize> {
        self.words.iter().position(|&s| s == word)
    }

    /// get the language of the word list.
    pub fn language(&self) -> Language {
        self.language
    }
}

//--------- BIP39 impls
impl BIP39 {
    /// create a new BIP39 by the given language.
    pub fn new(language: Language) -> Self {
        BIP39(WordList::new(language))
    }

    /// create new entropy bytes by the given bits size.
    /// the bits size must be a multiple of 32 and be within 128 and 256.
    pub fn new_entropy(&self, bits: usize) -> Result<Vec<u8>, Error> {
        if bits % 32 != 0 || bits < 128 || bits > 256 {
            return Err(Error::InvalidEntropyBits(bits));
        }

        let mut entropy = vec![0u8; bits / 8];
        rand::thread_rng().fill_bytes(&mut entropy);
        Ok(entropy)
    }

    /// add checksum to the given entropy bytes.
    pub fn add_checksum(&self, entropy: &[u8]) -> Vec<u8> {
        let mut checksum = vec![0u8; entropy.len() / 4];
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        let hash = hasher.finalize();
        for i in 0..checksum.len() {
            checksum[i] = hash[i];
        }
        let mut result = Vec::with_capacity(entropy.len() + checksum.len());
        result.extend_from_slice(entropy);
        result.extend_from_slice(&checksum);
        result
    }

    /// create new mnemonic by the given entropy bytes.
    pub fn new_mnemonic(&self, entropy: &[u8]) -> Result<String, Error> {
        let checksum = self.add_checksum(entropy);
        let mut result = Vec::with_capacity(checksum.len() * 3 / 4);
        for i in 0..checksum.len() * 3 / 4 {
            let index = (checksum[i / 3] >> (5 - (i % 3) * 2)) & 0x1f;
            result.push(self.0.get(index as usize).ok_or(Error::InvalidWordIndex(index as usize))?);
        }
        Ok(result.join(" "))
    }

    /// create new entropy bytes by the given mnemonic.
    pub fn new_entropy_from_mnemonic(&self, mnemonic: &str) -> Result<Vec<u8>, Error> {
        let words = wsplit(mnemonic);
        let word_count = words.len();
        let sentence_bits = word_count * 11;
        let ent_bits = sentence_bits - sentence_bits / 33;
        let ent_bytes = ent_bits / 8;

        if sentence_bits % 11 != 0 || ent_bits < 128 || ent_bits > 256 || ent_bits % 32 != 0 {
            return Err(Error::InvalidMnemonic(mnemonic.to_string()));
        }

        let mut result = Vec::with_capacity(ent_bytes);
        let mut bits = 0;
        let mut value = 0;

        for word in words {
            let index = self
                .0
                .index_of(word)
                .ok_or(Error::InvalidWord(word.to_string()))?;
            value = (value << 11) | (index as u32);
            bits += 11;

            if bits >= 8 {
                bits -= 8;
                result.push(((value >> bits) & 0xFF) as u8);
            }
        }

        if bits >= 5 {
            return Err(Error::InvalidMnemonic(mnemonic.to_string()));
        }

        let mut hasher = Sha256::new();
        hasher.update(&result);
        let hash = hasher.finalize();

        for i in 0..ent_bytes / 4 {
            if result[ent_bytes + i] != hash[i] {
                return Err(Error::InvalidMnemonic(mnemonic.to_string()));
            }
        }

        result.truncate(ent_bytes);
        Ok(result)
    }

    /// create new seed bytes by the given mnemonic and passphrase.
    pub fn new_seed(&self, mnemonic: &str, passphrase: &str) -> Result<Vec<u8>, Error> {
        let mut salt = String::with_capacity(8 + passphrase.len());
        salt.push_str("mnemonic");
        if !passphrase.is_empty() {
            salt.push_str(passphrase);
        }
        let salt = salt.as_bytes();

        let mut result = vec![0u8; 64];
        pbkdf2::<Hmac<Sha512>>(mnemonic.as_bytes(), salt, 2048, &mut result);
        Ok(result)
    }
}

/// Error is the error type for BIP39.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// InvalidEntropyBits is returned when the given entropy bits is invalid.
    InvalidEntropyBits(usize),
    /// InvalidWordIndex is returned when the given word index is invalid.
    InvalidWordIndex(usize),
    /// InvalidEntropy is returned when the given entropy is invalid.
    InvalidEntropy,
    /// InvalidMnemonic is returned when the given mnemonic is invalid.
    InvalidMnemonic(String),
    /// InvalidWord is returned when the given word is invalid.
    InvalidWord(String),
}
