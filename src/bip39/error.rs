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

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum ErrKind {
    InvalidChecksum,
    InvalidWord,
    InvalidWordCount(usize),
    InvalidEntropyLength(usize),
    InvalidMnemonicLength(usize),
}

impl std::fmt::Display for ErrKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidChecksum => write!(f, "Invalid checksum"),
            Self::InvalidWord => write!(f, "Invalid word"),
            Self::InvalidWordCount(count) => write!(f, "Invalid word count: {}", count),
            Self::InvalidEntropyLength(len) => write!(f, "Invalid entropy length: {}", len),
            Self::InvalidMnemonicLength(len) => write!(f, "Invalid mnemonic length: {}", len),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_checksum() {
        assert_eq!(
            ErrKind::InvalidChecksum.to_string(),
            "Invalid checksum"
        );
    }

    #[test]
    fn test_invalid_word() {
        assert_eq!(ErrKind::InvalidWord.to_string(), "Invalid word");
    }

    #[test]
    fn test_invalid_word_count() {
        assert_eq!(
            ErrKind::InvalidWordCount(12).to_string(),
            "Invalid word count: 12"
        );
    }

    #[test]
    fn test_invalid_entropy_length() {
        assert_eq!(
            ErrKind::InvalidEntropyLength(12).to_string(),
            "Invalid entropy length: 12"
        );
    }

    #[test]
    fn test_invalid_mnemonic_length() {
        assert_eq!(
            ErrKind::InvalidMnemonicLength(12).to_string(),
            "Invalid mnemonic length: 12"
        );
    }
}
