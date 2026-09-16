// SPDX-License-Identifier: Apache-2.0

//! BIP327 signing with owned, single-use secret nonces. No signature aggregation.

use alloc::{boxed::Box, vec::Vec};
use bitbox_secp256k1_sys as ffi;
use bitcoin::secp256k1::{PublicKey, ffi::CPtr};
use core::ptr;
use zeroize::Zeroizing;

use crate::SECP256K1;

/// Ordered key aggregation and its accumulated plain/x-only tweaks.
/// Opaque caches never cross the device protocol boundary.
pub struct KeyAgg {
    cache: ffi::secp256k1_musig_keyagg_cache,
    keys: Vec<PublicKey>,
}

impl KeyAgg {
    /// Aggregate compressed public keys in the supplied order (BIP327 KeyAgg).
    pub fn new(keys: &[[u8; 33]]) -> Result<Self, ()> {
        if keys.is_empty() {
            return Err(());
        }
        let keys = keys
            .iter()
            .map(|key| PublicKey::from_slice(key).map_err(|_| ()))
            .collect::<Result<Vec<_>, _>>()?;
        let pointers: Vec<_> = keys.iter().map(CPtr::as_c_ptr).collect();
        let mut cache = ffi::secp256k1_musig_keyagg_cache { data: [0; 197] };
        // SAFETY: nonempty array of initialized public keys, sized output, no scratch space.
        if unsafe {
            ffi::secp256k1_musig_pubkey_agg(
                SECP256K1.ctx().as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut cache,
                pointers.as_ptr(),
                pointers.len(),
            )
        } != 1
        {
            return Err(());
        }
        Ok(Self { cache, keys })
    }

    /// Return the full compressed aggregate key, retaining its parity for BIP32.
    pub fn public_key(&self) -> PublicKey {
        let mut key = core::mem::MaybeUninit::uninit();
        // SAFETY: only successful aggregation/tweaking can create this cache.
        assert_eq!(
            unsafe {
                ffi::secp256k1_musig_pubkey_get(
                    SECP256K1.ctx().as_ptr(),
                    key.as_mut_ptr(),
                    &self.cache,
                )
            },
            1
        );
        // SAFETY: successful call initialized the key.
        PublicKey::from(unsafe { key.assume_init() })
    }

    /// Apply a BIP32 plain tweak or a Taproot x-only tweak. Failure consumes the
    /// cache so an invalid intermediate state cannot be used to sign.
    pub fn tweak(mut self, tweak: &[u8; 32], xonly: bool) -> Result<Self, ()> {
        let f = if xonly {
            ffi::secp256k1_musig_pubkey_xonly_tweak_add
        } else {
            ffi::secp256k1_musig_pubkey_ec_tweak_add
        };
        // SAFETY: initialized cache and exactly 32 readable bytes. Output key is optional.
        if unsafe {
            f(
                SECP256K1.ctx().as_ptr(),
                ptr::null_mut(),
                &mut self.cache,
                tweak.as_ptr(),
            )
        } != 1
        {
            return Err(());
        }
        Ok(self)
    }
}

/// A public nonce validated by libsecp256k1. Its encoding is two compressed points.
pub struct PublicNonce(ffi::secp256k1_musig_pubnonce);

impl PublicNonce {
    /// Parse both points, rejecting invalid encodings and individual infinity points.
    pub fn parse(bytes: &[u8; 66]) -> Result<Self, ()> {
        let mut nonce = ffi::secp256k1_musig_pubnonce { data: [0; 132] };
        // SAFETY: the input/output sizes match the C API.
        if unsafe {
            ffi::secp256k1_musig_pubnonce_parse(
                SECP256K1.ctx().as_ptr(),
                &mut nonce,
                bytes.as_ptr(),
            )
        } != 1
        {
            return Err(());
        }
        Ok(Self(nonce))
    }

    /// Serialize a validated public nonce for BIP373.
    pub fn serialize(&self) -> [u8; 66] {
        let mut bytes = [0; 66];
        // SAFETY: nonce is initialized and the output is exactly 66 bytes.
        assert_eq!(
            unsafe {
                ffi::secp256k1_musig_pubnonce_serialize(
                    SECP256K1.ctx().as_ptr(),
                    bytes.as_mut_ptr(),
                    &self.0,
                )
            },
            1
        );
        bytes
    }
}

/// A nonce that can be consumed once. Never clone, serialize, or expose the
/// opaque secret. Heap ownership avoids copying it as a session moves.
pub struct SecretNonce {
    secret: Zeroizing<Box<[ffi::secp256k1_musig_secnonce]>>,
    public: PublicNonce,
    signer: PublicKey,
    aggregate: [u8; 33],
    message: [u8; 32],
}

/// Wipe the temporary keypair on every return path.
struct SigningKey(bitcoin::secp256k1::Keypair);
impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.non_secure_erase();
    }
}

impl SecretNonce {
    /// Generate a fresh nonce bound to the participant, aggregate and message.
    /// `random` must be freshly drawn secret randomness for every invocation;
    /// the public session identifier must never be used as this random input.
    pub fn generate(
        random: &[u8; 32],
        secret_key: &[u8; 32],
        keys: &KeyAgg,
        message: &[u8; 32],
        extra: &[u8; 32],
    ) -> Result<Self, ()> {
        let key = SigningKey(
            bitcoin::secp256k1::Keypair::from_seckey_slice(SECP256K1, secret_key)
                .map_err(|_| ())?,
        );
        let signer = key.0.public_key();
        if !keys.keys.contains(&signer) {
            return Err(());
        }
        let storage: Box<[_]> = Box::new([ffi::secp256k1_musig_secnonce { data: [0; 132] }]);
        let mut secret = Zeroizing::new(storage);
        let mut public = ffi::secp256k1_musig_pubnonce { data: [0; 132] };
        // SAFETY: valid participant key, initialized cache and fixed-size buffers.
        if unsafe {
            ffi::secp256k1_musig_nonce_gen(
                SECP256K1.ctx().as_ptr(),
                &mut secret[0],
                &mut public,
                random.as_ptr(),
                secret_key.as_ptr(),
                signer.as_c_ptr(),
                message.as_ptr(),
                &keys.cache,
                extra.as_ptr(),
            )
        } != 1
        {
            return Err(());
        }
        Ok(Self {
            secret,
            public: PublicNonce(public),
            signer,
            aggregate: keys.public_key().serialize(),
            message: *message,
        })
    }

    /// Return only the public nonce. The secret is never exported.
    pub fn public_nonce(&self) -> [u8; 66] {
        self.public.serialize()
    }

    /// Consume the nonce, aggregate the participants' public nonces and produce
    /// a verified partial signature. Nonces must follow the key aggregation order.
    /// Failure also destroys the secret nonce; callers must start a fresh session.
    pub fn sign(
        mut self,
        secret_key: &[u8; 32],
        keys: &KeyAgg,
        nonces: &[[u8; 66]],
        message: &[u8; 32],
    ) -> Result<[u8; 32], ()> {
        let key = SigningKey(
            bitcoin::secp256k1::Keypair::from_seckey_slice(SECP256K1, secret_key)
                .map_err(|_| ())?,
        );
        if key.0.public_key() != self.signer
            || keys.public_key().serialize() != self.aggregate
            || *message != self.message
            || nonces.len() != keys.keys.len()
        {
            return Err(());
        }
        let our_index = keys
            .keys
            .iter()
            .position(|key| *key == self.signer)
            .ok_or(())?;
        if nonces[our_index] != self.public_nonce() {
            return Err(());
        }
        let nonces = nonces
            .iter()
            .map(PublicNonce::parse)
            .collect::<Result<Vec<_>, _>>()?;
        let pointers: Vec<_> = nonces.iter().map(|nonce| &nonce.0 as *const _).collect();
        let mut aggregate = ffi::secp256k1_musig_aggnonce { data: [0; 132] };
        let mut session = ffi::secp256k1_musig_session { data: [0; 133] };
        let mut signature = ffi::secp256k1_musig_partial_sig { data: [0; 36] };
        // SAFETY: nonempty arrays of validated nonces, initialized matching cache,
        // participant keypair and live single-use nonce. All outputs have ABI sizes.
        unsafe {
            assert_eq!(
                ffi::secp256k1_musig_nonce_agg(
                    SECP256K1.ctx().as_ptr(),
                    &mut aggregate,
                    pointers.as_ptr(),
                    pointers.len()
                ),
                1
            );
            if ffi::secp256k1_musig_nonce_process(
                SECP256K1.ctx().as_ptr(),
                &mut session,
                &aggregate,
                message.as_ptr(),
                &keys.cache,
                ptr::null(),
            ) != 1
            {
                return Err(());
            }
            assert_eq!(
                ffi::secp256k1_musig_partial_sign(
                    SECP256K1.ctx().as_ptr(),
                    &mut signature,
                    &mut self.secret[0],
                    key.0.as_c_ptr(),
                    &keys.cache,
                    &session
                ),
                1
            );
            if ffi::secp256k1_musig_partial_sig_verify(
                SECP256K1.ctx().as_ptr(),
                &signature,
                &self.public.0,
                self.signer.as_c_ptr(),
                &keys.cache,
                &session,
            ) != 1
            {
                return Err(());
            }
            let mut bytes = [0; 32];
            assert_eq!(
                ffi::secp256k1_musig_partial_sig_serialize(
                    SECP256K1.ctx().as_ptr(),
                    bytes.as_mut_ptr(),
                    &signature
                ),
                1
            );
            Ok(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_lit::hex;

    /// Expected nonces and signatures are generated by the BIP327 v1.0.4
    /// Python reference, with fixed randomness only for this interoperability test.
    #[test]
    fn test_sign_reference() {
        let secrets = [
            hex!("0000000000000000000000000000000000000000000000000000000000000001"),
            hex!("0000000000000000000000000000000000000000000000000000000000000002"),
            hex!("0000000000000000000000000000000000000000000000000000000000000003"),
        ];
        let pubkeys = [
            hex!("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
            hex!("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
            hex!("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
        ];
        let message = [42; 32];
        let extra = [7; 32];
        {
            let keys = KeyAgg::new(&pubkeys).unwrap();
            assert_eq!(
                keys.public_key().serialize(),
                hex!("020a8111534296d6fef2b23ad86d0d982b7b2f0fe6a48f03b1827954da2026f8dc")
            );
            let public_nonces = [
                hex!(
                    "02c0f02c0b693e4afeefd27ec15e444e452ed2d9a15acb5c03a94c0aff5d8e52b103fc43a596f45e45c8006fb5e3a8425bd06edff943fd1f036e31a6d8d145347c2e"
                ),
                hex!(
                    "03f294a80261109a53c0873b7a75da5e9e9e424d93dc140fd757f77c9c648086ae029a93cb4adc5df0835443536370b5a11ec074fee7d9149799c7b11a3521f16eb8"
                ),
                hex!(
                    "035d999785452daedeb37d1dc343d5e8054dd421ab8d6e711391bddb0f942f2731033b7583691e496d346c2f98bbb6f37ae4ab396dcd4beac335323de627404ec839"
                ),
            ];
            let expected = [
                hex!("d70a13a16c398eea2a8cc63a39926a0c27aae76fcbcbdaaf6a99c24606667109"),
                hex!("9d987b78703a3d72436e3d5461239772e961992c61444b4e9009ca92310c7383"),
                hex!("880341f818679da44c09d24aa9b51d74bcbe47efd4b13aedd11ed94a4b6eb502"),
            ];
            for i in 0..secrets.len() {
                let nonce = SecretNonce::generate(
                    &[20 + i as u8; 32],
                    &secrets[i],
                    &keys,
                    &message,
                    &extra,
                )
                .unwrap();
                assert_eq!(nonce.public_nonce(), public_nonces[i]);
                assert_eq!(
                    nonce
                        .sign(&secrets[i], &keys, &public_nonces, &message)
                        .unwrap(),
                    expected[i]
                );
            }
        }
        {
            let keys = KeyAgg::new(&pubkeys).unwrap();
            let keys = keys.tweak(&[10; 32], false).unwrap();
            assert_eq!(
                keys.public_key().serialize(),
                hex!("03d2325d74eb23737f7611af638800586b0e4d59e8c998b538ba09fd52a476e12e")
            );
            let public_nonces = [
                hex!(
                    "020247faa17a8682aded26c00e2bf267a03c4fd5cf219ab7b1ad40835f53e6d0d4026831abe73b982d43db16e177be08bd6e9a1c0c46a6da270882096b1bdb3afbf0"
                ),
                hex!(
                    "023ab0dda5b068fd78e6a004349d6ddf87e427be7e788b142f4b98b83a89841ed50295785fd993296dfdafafa9966ab8c491460776f22d70bc1848807918613d69da"
                ),
                hex!(
                    "02e63c76b2000c3a1933d987edd702050ef8fbb2d9bfa9594ad44076fac4c3efee038ef213bcd19bef5e97b82b8463e266bd4514c1ba3a12bfaca5ffb54418fef70a"
                ),
            ];
            let expected = [
                hex!("38e2a9e80b12438a735486d47cfa03eb60ccf67095329227d37276caced04bf1"),
                hex!("e1cd2958460620967a952f97326d41cabb3a6faa633466b4347de2e12fcc5eea"),
                hex!("3ff9457a7ba882e975d7904884134dba322f48c4de22dcf695329115295a8f48"),
            ];
            for i in 0..secrets.len() {
                let nonce = SecretNonce::generate(
                    &[20 + i as u8; 32],
                    &secrets[i],
                    &keys,
                    &message,
                    &extra,
                )
                .unwrap();
                assert_eq!(nonce.public_nonce(), public_nonces[i]);
                assert_eq!(
                    nonce
                        .sign(&secrets[i], &keys, &public_nonces, &message)
                        .unwrap(),
                    expected[i]
                );
            }
        }
        {
            let keys = KeyAgg::new(&pubkeys).unwrap();
            let keys = keys.tweak(&[10; 32], true).unwrap();
            assert_eq!(
                keys.public_key().serialize(),
                hex!("03d2325d74eb23737f7611af638800586b0e4d59e8c998b538ba09fd52a476e12e")
            );
            let public_nonces = [
                hex!(
                    "020247faa17a8682aded26c00e2bf267a03c4fd5cf219ab7b1ad40835f53e6d0d4026831abe73b982d43db16e177be08bd6e9a1c0c46a6da270882096b1bdb3afbf0"
                ),
                hex!(
                    "023ab0dda5b068fd78e6a004349d6ddf87e427be7e788b142f4b98b83a89841ed50295785fd993296dfdafafa9966ab8c491460776f22d70bc1848807918613d69da"
                ),
                hex!(
                    "02e63c76b2000c3a1933d987edd702050ef8fbb2d9bfa9594ad44076fac4c3efee038ef213bcd19bef5e97b82b8463e266bd4514c1ba3a12bfaca5ffb54418fef70a"
                ),
            ];
            let expected = [
                hex!("38e2a9e80b12438a735486d47cfa03eb60ccf67095329227d37276caced04bf1"),
                hex!("e1cd2958460620967a952f97326d41cabb3a6faa633466b4347de2e12fcc5eea"),
                hex!("3ff9457a7ba882e975d7904884134dba322f48c4de22dcf695329115295a8f48"),
            ];
            for i in 0..secrets.len() {
                let nonce = SecretNonce::generate(
                    &[20 + i as u8; 32],
                    &secrets[i],
                    &keys,
                    &message,
                    &extra,
                )
                .unwrap();
                assert_eq!(nonce.public_nonce(), public_nonces[i]);
                assert_eq!(
                    nonce
                        .sign(&secrets[i], &keys, &public_nonces, &message)
                        .unwrap(),
                    expected[i]
                );
            }
        }
        {
            let keys = KeyAgg::new(&pubkeys).unwrap();
            let keys = keys.tweak(&[10; 32], false).unwrap();
            let keys = keys.tweak(&[11; 32], true).unwrap();
            assert_eq!(
                keys.public_key().serialize(),
                hex!("03d4b796bc7728f63135e1a03682a27253d5a5c049dc7ed259bc1b1502702d8905")
            );
            let public_nonces = [
                hex!(
                    "03fecd7273b35b4e976422656411f6a240484f820b8d9baaefca027ea7eb6a369202ea15aa384819b0d0e8a3657c7915c6cd3949b3f2e852039fb5d083caca313fa5"
                ),
                hex!(
                    "0382b0ea2bdbb4b62de3bb9fc60bde72c151c10745a22d123b1b1fe31de3780fc3038ff2f924a484484db082e3c913001732a01485faa5a2273108d7b35b258ec57d"
                ),
                hex!(
                    "0211dce4d7dc655cf0939502463655bc40f780c213c30980fa1b6f30731bccb70402438490022c535155d57f06e06001d0fd68789567bba72963067787844cb09133"
                ),
            ];
            let expected = [
                hex!("e10638260e034bc5a87becfd6fe5cc05a08c3a697cc53e3700ac13a98b23adb6"),
                hex!("69871e100442f8546dcdd68110c02d421d5f0ba79e15e16ffc134bbff21212a8"),
                hex!("90eb117ecec2d8a8512a7ce09a4a8b3f22ce638196c10c0f6bc00e1b92a5f059"),
            ];
            for i in 0..secrets.len() {
                let nonce = SecretNonce::generate(
                    &[20 + i as u8; 32],
                    &secrets[i],
                    &keys,
                    &message,
                    &extra,
                )
                .unwrap();
                assert_eq!(nonce.public_nonce(), public_nonces[i]);
                assert_eq!(
                    nonce
                        .sign(&secrets[i], &keys, &public_nonces, &message)
                        .unwrap(),
                    expected[i]
                );
            }
        }
        {
            let keys = KeyAgg::new(&pubkeys).unwrap();
            let keys = keys.tweak(&[10; 32], true).unwrap();
            let keys = keys.tweak(&[11; 32], false).unwrap();
            let keys = keys.tweak(&[12; 32], true).unwrap();
            assert_eq!(
                keys.public_key().serialize(),
                hex!("02068833323bfe3caf4393cc29ae3b71fc59df71ef60b114a26f7e38c993214b88")
            );
            let public_nonces = [
                hex!(
                    "028f93df3df466861fe6f56bf4b7a76afbb83c9983bb37b31024b7b0d654b3890802a84f391785d70a6ba24957fef8dd8637b56c2974237adcf5e6052d5d34585286"
                ),
                hex!(
                    "03e256011d840f16a1fb086fba33cdf72f56eadaec61a1505ee6e94f1fd5d715e0035405e546bfade02af529b719bc465e53bf1468e41fdd81e300d9ab1f1d34352f"
                ),
                hex!(
                    "037409072cebe827ac952d81cc8abde6c4792307d4284a18a676e0c22d289fe1c702177661ab1b42232705645dca84732000903295627baba1bd7459fad6d87840f3"
                ),
            ];
            let expected = [
                hex!("ef5cc0828a55f105263d6e1c4a6f1056fa4db6a6414502767c30896e3165eac1"),
                hex!("c86853d06c58af57748eb32745722da128e2ca7d62c6ef160ed00d28c642a9e5"),
                hex!("368888e3155f7064827e1e257fb7c87ea892d518b932a34ed4c37289997a470c"),
            ];
            for i in 0..secrets.len() {
                let nonce = SecretNonce::generate(
                    &[20 + i as u8; 32],
                    &secrets[i],
                    &keys,
                    &message,
                    &extra,
                )
                .unwrap();
                assert_eq!(nonce.public_nonce(), public_nonces[i]);
                assert_eq!(
                    nonce
                        .sign(&secrets[i], &keys, &public_nonces, &message)
                        .unwrap(),
                    expected[i]
                );
            }
        }
    }

    #[test]
    fn test_sign_rejects_changed_context() {
        let secret = [1; 32];
        let key =
            SigningKey(bitcoin::secp256k1::Keypair::from_seckey_slice(SECP256K1, &secret).unwrap());
        let keys = KeyAgg::new(&[key.0.public_key().serialize()]).unwrap();
        for mode in 0..4 {
            let nonce =
                SecretNonce::generate(&[2; 32], &secret, &keys, &[3; 32], &[4; 32]).unwrap();
            let mut public = [nonce.public_nonce()];
            let mut message = [3; 32];
            let mut signing_key = secret;
            match mode {
                0 => message[0] ^= 1,
                1 => signing_key[0] ^= 1,
                2 => public[0][0] ^= 1,
                _ => public[0] = [0; 66],
            }
            assert!(nonce.sign(&signing_key, &keys, &public, &message).is_err());
        }
        assert!(KeyAgg::new(&[]).is_err());
        assert!(KeyAgg::new(&[[0; 33]]).is_err());
        assert!(keys.tweak(&[255; 32], false).is_err());
        assert!(PublicNonce::parse(&[0; 66]).is_err());
    }
}

/// Verify a peer's contribution against independently computed transaction data.
/// Only test/host builds need this; firmware already verifies its own contribution.
#[cfg(any(test, feature = "testing"))]
pub fn verify_partial(
    keys: &KeyAgg,
    nonces: &[[u8; 66]],
    message: &[u8; 32],
    signer: usize,
    signature: &[u8; 32],
) -> Result<(), ()> {
    if nonces.len() != keys.keys.len() || signer >= nonces.len() {
        return Err(());
    }
    let nonces = nonces
        .iter()
        .map(PublicNonce::parse)
        .collect::<Result<Vec<_>, _>>()?;
    let pointers: Vec<_> = nonces.iter().map(|nonce| &nonce.0 as *const _).collect();
    let mut aggregate = ffi::secp256k1_musig_aggnonce { data: [0; 132] };
    let mut session = ffi::secp256k1_musig_session { data: [0; 133] };
    let mut sig = ffi::secp256k1_musig_partial_sig { data: [0; 36] };
    // SAFETY: the nonempty list contains parsed nonce objects; the cache is
    // initialized and all buffers have the fixed lengths required by the ABI.
    unsafe {
        assert_eq!(
            ffi::secp256k1_musig_nonce_agg(
                SECP256K1.ctx().as_ptr(),
                &mut aggregate,
                pointers.as_ptr(),
                pointers.len()
            ),
            1
        );
        if ffi::secp256k1_musig_nonce_process(
            SECP256K1.ctx().as_ptr(),
            &mut session,
            &aggregate,
            message.as_ptr(),
            &keys.cache,
            ptr::null(),
        ) != 1
            || ffi::secp256k1_musig_partial_sig_parse(
                SECP256K1.ctx().as_ptr(),
                &mut sig,
                signature.as_ptr(),
            ) != 1
            || ffi::secp256k1_musig_partial_sig_verify(
                SECP256K1.ctx().as_ptr(),
                &sig,
                &nonces[signer].0,
                keys.keys[signer].as_c_ptr(),
                &keys.cache,
                &session,
            ) != 1
        {
            return Err(());
        }
    }
    Ok(())
}
