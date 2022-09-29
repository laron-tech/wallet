# laron-wallet

![build](https://github.com/laron-tech/wallet/actions/workflows/rust.yml/badge.svg)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![crates.io](https://img.shields.io/crates/v/laron-wallet.svg)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcuriousdev04%2Fwallet.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcuriousdev04%2Fwallet?ref=badge_shield)

This is a library for generating and managing wallets. This library contains
the following features:
- BIP39 Mnemonic and Seed Generation
- BIP32 HD Wallet Generation

## TODO
- [ ] Add support RPC calls
- [ ] Add support for Contracts

### Example
```rust
use laron_wallet::bips::bip39::{Mnemonic, MnemonicType};
use laron_wallet::bips::wordlists::Language;
use laron_wallet::bips::bip32::ExtendedKey;
use laron_wallet::bips::DerivationPath;

let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
let seed = mnemonic.to_seed("password");
let master_key = ExtendedKey::new_master(&seed).unwrap();

// define the path to derive, We will use ethereum path
let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
let child_key = master_key.derive_path(&path).unwrap();
let private_key = child_key.private_key();
let public_key = private_key.public_key();
let address = public_key.address();
```

License: GPL-3.0-or-later
