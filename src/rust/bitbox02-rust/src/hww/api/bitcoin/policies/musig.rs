// SPDX-License-Identifier: Apache-2.0

//! BIP388 MuSig placeholders and BIP328 aggregate public derivation.

use super::*;
use alloc::string::ToString;
use bitbox_secp256k1::musig::KeyAgg;
use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::hashes::Hash;

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

/// Verified policy context for one participant's contribution.
pub struct SigningContext {
    pub aggregate: KeyAgg,
    pub participants: Vec<[u8; 33]>,
    pub bare_key: [u8; 33],
    pub internal_key: [u8; 33],
    pub keypath: Vec<u32>,
    pub participant: [u8; 33],
    pub tapleaf_hash: Option<[u8; 32]>,
}

impl ParsedPolicy<'_> {
    /// Resolve an explicit aggregate expression and address selector to a spend.
    /// The selector consists of our participant's origin path followed by the
    /// aggregate branch/index; only the origin path is used for private derivation.
    pub fn musig_context(
        &self,
        expression: &str,
        selector: &[u32],
    ) -> Result<SigningContext, Error> {
        if !self.iter_pk().any(|key| key == expression) {
            return Err(Error::InvalidInput);
        }
        let placeholder = Placeholder::parse(expression)?;
        if !placeholder.musig || selector.len() < 2 {
            return Err(Error::InvalidInput);
        }
        let origin = &selector[..selector.len() - 2];
        let key_index = placeholder
            .indexes
            .iter()
            .copied()
            .find(|&i| {
                self.is_our_key.get(i) == Some(&true) && self.policy.keys[i].keypath == origin
            })
            .ok_or(Error::InvalidInput)?;
        let branch = selector[selector.len() - 2];
        let change = if branch == placeholder.left {
            false
        } else if branch == placeholder.right {
            true
        } else {
            return Err(Error::InvalidInput);
        };
        let index = selector[selector.len() - 1];
        let (mut aggregate, participants, bare_key) =
            placeholder.derive(&self.policy.keys, change, index)?;
        let internal_key = aggregate.public_key().serialize();
        let Descriptor::Tr(derived) = self.derive(change, index)? else {
            return Err(Error::InvalidInput);
        };
        let Descriptor::Tr(template) = &self.descriptor else {
            return Err(Error::InvalidInput);
        };
        let tapleaf_hash = if template.inner.internal_key() == expression {
            let spend = derived.inner.spend_info();
            let tweak = TapTweakHash::from_key_and_tweak(spend.internal_key(), spend.merkle_root());
            aggregate = aggregate
                .tweak(tweak.as_byte_array(), true)
                .map_err(|_| Error::InvalidInput)?;
            if aggregate.public_key().x_only_public_key().0.serialize() != derived.output_key() {
                return Err(Error::Generic);
            }
            None
        } else {
            Some(
                derived
                    .get_leaf_hash_by_pubkey(&internal_key)
                    .ok_or(Error::InvalidInput)?
                    .to_byte_array(),
            )
        };
        Ok(SigningContext {
            aggregate,
            participants,
            bare_key,
            internal_key,
            keypath: origin.to_vec(),
            participant: self.policy.keys[key_index]
                .xpub
                .as_ref()
                .ok_or(Error::InvalidInput)?
                .public_key
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidInput)?,
            tapleaf_hash,
        })
    }
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

    #[async_test::test]
    async fn test_musig_context() {
        crate::keystore::testing::mock_unlocked();
        let mut hal = TestingHal::new();
        let origin = vec![48 + HARDENED, 1 + HARDENED, HARDENED, 3 + HARDENED];
        let ours = pb::KeyOriginInfo {
            root_fingerprint: crate::keystore::root_fingerprint().unwrap(),
            keypath: origin.clone(),
            xpub: Some(
                crate::keystore::get_xpub(&mut hal, &origin, crate::keystore::Compute::Once)
                    .await
                    .unwrap()
                    .into(),
            ),
        };
        let mut other = ours.clone();
        other.root_fingerprint.clear();
        let external =
            bitcoin::bip32::Xpriv::new_master(bitcoin::NetworkKind::Test, &[17; 32]).unwrap();
        other.xpub =
            Some(bip32::Xpub::from(Xpub::from_priv(crate::secp256k1::SECP256K1, &external)).into());
        let selector: Vec<_> = origin.iter().copied().chain([1, 5]).collect();
        for expression in ["tr(musig(@0,@1)/**)", "tr(@0/<2;3>/*,pk(musig(@0,@1)/**))"] {
            let policy = Policy {
                policy: expression.into(),
                keys: vec![ours.clone(), other.clone()],
            };
            let parsed = parse(&mut hal, &policy, BtcCoin::Tbtc).await.unwrap();
            let ctx = parsed.musig_context("musig(@0,@1)/**", &selector).unwrap();
            assert_eq!(ctx.keypath, origin);
            assert_eq!(
                ctx.participant.as_slice(),
                ours.xpub.as_ref().unwrap().public_key
            );
            assert_eq!(ctx.participants.len(), 2);
            assert!(ctx.participants[0] < ctx.participants[1]);
            assert_eq!(ctx.tapleaf_hash.is_some(), expression.starts_with("tr(@"));
            assert!(parsed.is_change_keypath(&selector).unwrap());
            assert!(parsed.musig_context("musig(@0,@2)/**", &selector).is_err());
            let mut hardened = selector.clone();
            *hardened.last_mut().unwrap() = HARDENED;
            assert!(parsed.musig_context("musig(@0,@1)/**", &hardened).is_err());
            // Compare the aggregate child against independent BIP32 CKDpub.
            let bare = bitcoin::secp256k1::PublicKey::from_slice(&ctx.bare_key).unwrap();
            let synthetic = Xpub {
                network: bitcoin::NetworkKind::Main,
                depth: 0,
                parent_fingerprint: Fingerprint::default(),
                child_number: ChildNumber::from(0),
                public_key: bare,
                chain_code: ChainCode::from(hex_lit::hex!(
                    "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"
                )),
            };
            let child = synthetic
                .derive_pub(
                    crate::secp256k1::SECP256K1,
                    &bip32::keypath_from_slice(&[1, 5]),
                )
                .unwrap();
            assert_eq!(ctx.internal_key, child.public_key.serialize());
        }
    }
}
