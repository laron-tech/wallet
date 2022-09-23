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

use std::collections::HashMap;

use super::error::ErrKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordMap {
    data: HashMap<String, u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordList {
    data: Vec<&'static str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    #[cfg(feature = "chinese_simplified")]
    ChineseSimplified,
    #[cfg(feature = "chinese_traditional")]
    ChineseTraditional,
    #[cfg(feature = "czech")]
    Czech,
    English,
    #[cfg(feature = "french")]
    French,
    #[cfg(feature = "italian")]
    Italian,
    #[cfg(feature = "japanese")]
    Japanese,
    #[cfg(feature = "korean")]
    Korean,
    #[cfg(feature = "spanish")]
    Spanish,
}

impl Language {
    pub fn word_list(&self) -> WordList {
        match self {
            #[cfg(feature = "chinese_simplified")]
            Language::ChineseSimplified => WordList {
                data: include_str!("./wordlists/chinese_simplified.txt")
                    .split_whitespace()
                    .collect(),
            },
            #[cfg(feature = "chinese_traditional")]
            Language::ChineseTraditional => WordList {
                data: include_str!("./wordlists/chinese_traditional.txt")
                    .split_whitespace()
                    .collect(),
            },
            #[cfg(feature = "czech")]
            Language::Czech => WordList {
                data: include_str!("./wordlists/czech.txt")
                    .split_whitespace()
                    .collect(),
            },
            Language::English => WordList {
                data: include_str!("./wordlists/english.txt")
                    .split_whitespace()
                    .collect(),
            },
            #[cfg(feature = "french")]
            Language::French => WordList {
                data: include_str!("./wordlists/french.txt")
                    .split_whitespace()
                    .collect(),
            },
            #[cfg(feature = "italian")]
            Language::Italian => WordList {
                data: include_str!("./wordlists/italian.txt")
                    .split_whitespace()
                    .collect(),
            },
            #[cfg(feature = "japanese")]
            Language::Japanese => WordList {
                data: include_str!("./wordlists/japanese.txt")
                    .split_whitespace()
                    .collect(),
            },
            #[cfg(feature = "korean")]
            Language::Korean => WordList {
                data: include_str!("./wordlists/korean.txt")
                    .split_whitespace()
                    .collect(),
            },
            #[cfg(feature = "spanish")]
            Language::Spanish => WordList {
                data: include_str!("./wordlists/spanish.txt")
                    .split_whitespace()
                    .collect(),
            },
        }
    }

    pub fn word_map(&self) -> WordMap {
        let mut map = HashMap::new();
        for (i, word) in self.word_list().data.iter().enumerate() {
            map.insert(word.to_string(), i as u16);
        }
        WordMap { data: map }
    }
}

impl Default for Language {
    fn default() -> Self {
        Language::English
    }
}

impl WordList {
    pub fn get(&self, index: u16) -> &'static str {
        self.data[index as usize]
    }

    pub fn get_word_by_prefix(&self, prefix: &str) -> &[&'static str] {
        let start = self
            .data
            .binary_search(&prefix)
            .unwrap_or_else(|x| x);
        let count = self.data[start..]
            .iter()
            .take_while(|x| x.starts_with(prefix))
            .count();
        &self.data[start..start + count]
    }
}

impl WordMap {
    pub fn get_index(&self, word: &str) -> Result<u16, ErrKind> {
        self.data.get(word).cloned().ok_or(ErrKind::InvalidWord)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_word_by_prefix() {
        let words = Language::English.word_list();
        assert_eq!(words.get_word_by_prefix("abo"), &["about", "above"]);
    }

    #[test]
    fn test_word_map() {
        let map = Language::English.word_map();
        assert_eq!(map.get_index("about").unwrap(), 3);
        assert_eq!(map.get_index("above").unwrap(), 4);
        assert!(map.get_index("abou").is_err());
    }

    #[test]
    fn test_word_list() {
        let words = Language::English.word_list();
        assert_eq!(words.get(3), "about");
        assert_eq!(words.get(4), "above");
    }
}
