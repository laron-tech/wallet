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

use rand::Rng;
use sha2::{Digest, Sha256};

use super::{error::ErrKind, Language};

#[derive(Clone)]
pub struct Mnemonic {
    entropy: Vec<u8>,
    language: Language,
    phrase: String,
}

impl Mnemonic {
    /// Create a new mnemonic by the given entropy size (multiple of 32 and between 128 ~ 256), and
    /// by the prefered language.
    pub fn new(size: u16, lang: Language) -> Result<Self, ErrKind> {
        if size % 32 != 0 || !(128..256).contains(&size) {
            return Err(ErrKind::InvalidEntropyLength(size as usize));
        }

        let mut bytes = vec![0u8; size as usize / 8];
        rand::thread_rng().fill(&mut bytes[..]);

        Ok(Self::from_entropy_unchecked(&bytes, lang))
    }

    /// Create a new mnemonic by the given entropy, and by the prefered language.
    pub fn from_entropy_unchecked(ent: &[u8], lang: Language) -> Self {
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
            .map(|chunk| chunk.iter().fold(0u16, |acc, bit| (acc << 1) | (*bit as u16)))
            .map(|idx| word_list.get(idx))
            .collect::<Vec<_>>()
            .join(" ");

        Mnemonic {
            entropy,
            language: lang,
            phrase,
        }
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
