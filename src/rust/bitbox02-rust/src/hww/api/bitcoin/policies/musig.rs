// SPDX-License-Identifier: Apache-2.0

//! BIP388 MuSig placeholders and BIP328 aggregate public derivation.

use super::*;
use alloc::string::ToString;
use bitbox_secp256k1::musig::KeyAgg;
use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};

/// A policy key and its two public receive/change branches.
pub(super) struct Placeholder {
    pub indexes: Vec<usize>,
    pub left: u32,
    pub right: u32,
    pub musig: bool,
}

impl Placeholder {
    /// Parse an ordinary key or a BIP388 aggregate-before-derivation key.
    pub fn parse(key: &str) -> Result<Self, Error> {
        if let Some(rest) = key.strip_prefix("musig(") {
            let (participants, derivation) = rest.split_once(")/").ok_or(Error::InvalidInput)?;
            let (_, left, right) = parse_wallet_policy_pk(&format!("@0/{}", derivation))
                .map_err(|_| Error::InvalidInput)?;
            let mut indexes = Vec::new();
            for participant in participants.split(',') {
                let (index, _, _) = parse_wallet_policy_pk(&format!("{}/**", participant))
                    .map_err(|_| Error::InvalidInput)?;
                if indexes.len() >= MAX_KEYS || indexes.contains(&index) {
                    return Err(Error::InvalidInput);
                }
                indexes.push(index);
            }
            if indexes.len() < 2 {
                return Err(Error::InvalidInput);
            }
            Ok(Self {
                indexes,
                left,
                right,
                musig: true,
            })
        } else {
            let (index, left, right) =
                parse_wallet_policy_pk(key).map_err(|_| Error::InvalidInput)?;
            Ok(Self {
                indexes: vec![index],
                left,
                right,
                musig: false,
            })
        }
    }

    /// Compute ordered participant keys and the bare aggregate, then derive the
    /// selected BIP328 child. Participant private keys do not follow this path.
    pub fn derive(
        &self,
        keys: &[pb::KeyOriginInfo],
        change: bool,
        index: u32,
    ) -> Result<(KeyAgg, Vec<[u8; 33]>, [u8; 33]), Error> {
        if !self.musig || index >= HARDENED {
            return Err(Error::InvalidInput);
        }
        let mut participants = self
            .indexes
            .iter()
            .map(|&i| {
                let key = keys
                    .get(i)
                    .and_then(|key| key.xpub.as_ref())
                    .ok_or(Error::InvalidInput)?;
                key.public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::InvalidInput)
            })
            .collect::<Result<Vec<[u8; 33]>, Error>>()?;
        participants.sort_unstable();
        if participants.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::InvalidInput);
        }
        let mut aggregate = KeyAgg::new(&participants).map_err(|_| Error::InvalidInput)?;
        let bare = aggregate.public_key().serialize();
        let mut xpub = Xpub {
            network: bitcoin::NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::from(0),
            public_key: aggregate.public_key(),
            chain_code: ChainCode::from(hex_lit::hex!(
                "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"
            )),
        };
        for child in [if change { self.right } else { self.left }, index] {
            let child = ChildNumber::from_normal_idx(child).map_err(|_| Error::InvalidInput)?;
            let (tweak, _) = xpub.ckd_pub_tweak(child).map_err(|_| Error::InvalidInput)?;
            aggregate = aggregate
                .tweak(&tweak.secret_bytes(), false)
                .map_err(|_| Error::InvalidInput)?;
            xpub = xpub
                .ckd_pub(crate::secp256k1::SECP256K1, child)
                .map_err(|_| Error::InvalidInput)?;
            if aggregate.public_key() != xpub.public_key {
                return Err(Error::Generic);
            }
        }
        Ok((aggregate, participants, bare))
    }
}

/// Miniscript 13 parses key strings as terminal nodes. Temporarily replace the
/// parentheses in MuSig keys, then restore the original key strings before
/// validation/derivation. This adds no new script fragments or descriptor types.
pub(super) fn parse_tr(template: &str) -> Result<miniscript::descriptor::Tr<String>, Error> {
    const PREFIX: &str = "__musig";
    if template.contains(PREFIX) {
        return Err(Error::InvalidInput);
    }
    let mut remaining = template;
    let mut normalized = String::new();
    let mut aggregates = Vec::new();
    while let Some(start) = remaining.find("musig(") {
        let end = remaining[start..].find(')').ok_or(Error::InvalidInput)? + start + 1;
        if aggregates.len() >= MAX_KEYS {
            return Err(Error::InvalidInput);
        }
        normalized.push_str(&remaining[..start]);
        normalized.push_str(&format!("{}{}", PREFIX, aggregates.len()));
        aggregates.push(remaining[start..end].to_string());
        remaining = &remaining[end..];
    }
    normalized.push_str(remaining);
    struct Restore(Vec<String>);
    impl miniscript::Translator<String> for Restore {
        type TargetPk = String;
        type Error = Error;
        fn pk(&mut self, pk: &String) -> Result<String, Error> {
            match pk.strip_prefix(PREFIX) {
                None => Ok(pk.clone()),
                Some(rest) => {
                    let (index, suffix) = rest.split_once('/').ok_or(Error::InvalidInput)?;
                    let index: usize = index.parse().map_err(|_| Error::InvalidInput)?;
                    Ok(format!(
                        "{}/{}",
                        self.0.get(index).ok_or(Error::InvalidInput)?,
                        suffix
                    ))
                }
            }
        }
        // Hash fragments are kept as they are, so that parsing rejects them.
        fn sha256(&mut self, hash: &String) -> Result<String, Error> {
            Ok(hash.clone())
        }
        fn hash256(&mut self, hash: &String) -> Result<String, Error> {
            Ok(hash.clone())
        }
        fn ripemd160(&mut self, hash: &String) -> Result<String, Error> {
            Ok(hash.clone())
        }
        fn hash160(&mut self, hash: &String) -> Result<String, Error> {
            Ok(hash.clone())
        }
    }
    let tr = miniscript::descriptor::Tr::<String>::from_str(&normalized)
        .map_err(|_| Error::InvalidInput)?;
    tr.translate_pk(&mut Restore(aggregates))
        .map_err(|_| Error::InvalidInput)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::testing::TestingHal;

    #[test]
    fn test_placeholder_parse() {
        let p = Placeholder::parse("musig(@1,@0)/<2;3>/*").unwrap();
        assert_eq!(p.indexes, [1, 0]);
        assert_eq!((p.left, p.right), (2, 3));
        for invalid in [
            "musig(@0)/**",
            "musig(@0,@0)/**",
            "musig(@01,@2)/**",
            "musig(@0/**,@1/**)",
            "musig(@0,musig(@1,@2))/**",
            "musig(@0,@1)/<0;0>/*",
        ] {
            assert!(Placeholder::parse(invalid).is_err(), "{}", invalid);
        }
    }

    #[test]
    fn test_placeholder_derive() {
        // Test vector of BIP-390: the scriptPubKeys of
        // `rawtr(musig(xpub6ERA...,xpub68NZ...)/0/*)` at the indexes 0, 1 and 2, whose output keys
        // are the derived aggregate keys.
        let keys: Vec<pb::KeyOriginInfo> = [
            "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
            "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y",
        ]
        .iter()
        .map(|xpub| pb::KeyOriginInfo {
            xpub: Some(crate::bip32::parse_xpub(xpub).unwrap()),
            ..Default::default()
        })
        .collect();
        let placeholder = Placeholder::parse("musig(@0,@1)/**").unwrap();
        let expected = [
            hex_lit::hex!("9508c08832f3bb9d5e8baf8cb5cfa3669902e2f2da19acea63ff47b93faa9bfc"),
            hex_lit::hex!("5ca1102663025a83dd9b5dbc214762c5a6309af00d48167d2d6483808525a298"),
            hex_lit::hex!("7dbed1b89c338df6a1ae137f133a19cae6e03d481196ee6f1a5c7d1aeb56b166"),
        ];
        for (index, expected) in expected.iter().enumerate() {
            let (aggregate, _, _) = placeholder.derive(&keys, false, index as u32).unwrap();
            assert_eq!(
                aggregate.public_key().x_only_public_key().0.serialize(),
                *expected
            );
        }
    }
}
