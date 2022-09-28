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

//! # BIP39 Mnemonic and Seed Generation
//!
//! This module implements the BIP39 standard for mnemonic generation and seed
//! generation. It is used to generate a mnemonic phrase from a given entropy
//! and to generate a seed from a given mnemonic phrase and a password.
//! The seed can be used to generate a master private key.
//!
//! ## Example
//! ```rust
//! use laron_wallet::bips::bip39::{Mnemonic, MnemonicType};
//! use laron_wallet::bips::wordlists::Language;
//!
//! let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
//! let seed = mnemonic.to_seed("password");
//! ```

mod mnemonic;
mod seed;

pub use mnemonic::*;
pub use seed::*;
