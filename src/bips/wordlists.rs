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

//! Language of the wordlist as defined in
//! [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
//!
//! The wordlist is a list of words that can be used to generate a mnemonic.
//! At the moment, only 10 languages are supported.
//! - English
//! - Chinese (Simplified)
//! - Chinese (Traditional)
//! - French
//! - Italian
//! - Japanese
//! - Korean
//! - Spanish
//! - Portuguese
//! - Czech
//!
//! # Example
//! ```rust
//! use laron_wallet::bips::wordlists::Language;
//!
//! let lang = Language::English;
//! let wordlist = lang.wordlist(); // returns a list of words
//! assert_eq!(wordlist.get(0).unwrap(), "abandon");
//! ```
//!
//! You can also using another language by adding the feature flag on the Cargo.toml
//! ```toml
//! [dependencies]
//! laron-wallet = { version = "0.1", features = ["chinese_simplified"] }
//! ```

use horror::Result;
use std::collections::HashMap;

/// Error returned when a word is not found in a wordlist or error
/// occurs while reading the wordlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordListError {
    InvalidWord,
}

impl std::fmt::Display for WordListError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            WordListError::InvalidWord => write!(f, "Invalid word"),
        }
    }
}

impl std::error::Error for WordListError {}

/// A wordlist is a list of words that can be used to generate a mnemonic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordList(Vec<&'static str>);

impl WordList {
    /// Get the word at the given index.
    pub fn get(&self, index: usize) -> Result<&'static str> {
        if index >= self.0.len() {
            return Err(WordListError::InvalidWord.into());
        }
        Ok(self.0[index])
    }

    /// Get list of words by the given prefix.
    pub fn get_word_by_prefix(&self, prefix: &str) -> &[&'static str] {
        let start = self.0.binary_search(&prefix).unwrap_or_else(|e| e);

        let count = self.0[start..]
            .iter()
            .take_while(|w| w.starts_with(prefix))
            .count();

        &self.0[start..start + count]
    }
}

/// A wordmap is a map of words to their index in a wordlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordMap(HashMap<&'static str, usize>);

impl WordMap {
    /// get the index of the given word.
    pub fn get_index(&self, word: &str) -> Result<usize> {
        self.0
            .get(word)
            .cloned()
            .ok_or_else(|| WordListError::InvalidWord.into())
    }
}

/// Language of the wordlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    English,
    #[cfg(feature = "chinese_simplified")]
    ChineseSimplified,
    #[cfg(feature = "chinese_traditional")]
    ChineseTraditional,
    #[cfg(feature = "czech")]
    Czech,
    #[cfg(feature = "french")]
    French,
    #[cfg(feature = "italian")]
    Italian,
    #[cfg(feature = "japanese")]
    Japanese,
    #[cfg(feature = "korean")]
    Korean,
    #[cfg(feature = "portuguese")]
    Portuguese,
    #[cfg(feature = "spanish")]
    Spanish,
}

impl Language {
    /// Get the wordlist for the given language.
    pub fn wordlist(self) -> WordList {
        match self {
            Language::English => WordList(
                include_str!("./wordlists/english.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "chinese_simplified")]
            Language::ChineseSimplified => WordList(
                include_str!("./wordlists/chinese_simplified.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "chinese_traditional")]
            Language::ChineseTraditional => WordList(
                include_str!("./wordlists/chinese_traditional.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "czech")]
            Language::Czech => WordList(
                include_str!("./wordlists/czech.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "french")]
            Language::French => WordList(
                include_str!("./wordlists/french.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "italian")]
            Language::Italian => WordList(
                include_str!("./wordlists/italian.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "japanese")]
            Language::Japanese => WordList(
                include_str!("./wordlists/japanese.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "korean")]
            Language::Korean => WordList(
                include_str!("./wordlists/korean.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "portuguese")]
            Language::Portuguese => WordList(
                include_str!("./wordlists/portuguese.txt")
                    .split_whitespace()
                    .collect(),
            ),
            #[cfg(feature = "spanish")]
            Language::Spanish => WordList(
                include_str!("./wordlists/spanish.txt")
                    .split_whitespace()
                    .collect(),
            ),
        }
    }

    /// Get the wordmap for the given language.
    pub fn wordmap(self) -> WordMap {
        let mut map = HashMap::new();
        for (i, word) in self.wordlist().0.iter().enumerate() {
            map.insert(*word, i);
        }
        WordMap(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist() {
        let wordlist = Language::English.wordlist();
        assert_eq!(wordlist.get(0).unwrap(), "abandon");
        assert_eq!(wordlist.get(2047).unwrap(), "zoo");
        assert!(wordlist.get(2048).is_err());
    }

    #[test]
    fn test_wordmap() {
        let wordmap = Language::English.wordmap();
        assert_eq!(wordmap.get_index("abandon").unwrap(), 0);
        assert_eq!(wordmap.get_index("zoo").unwrap(), 2047);
        assert!(wordmap.get_index("zonee").is_err());
    }
}
