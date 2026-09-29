// SPDX-License-Identifier: Apache-2.0

extern crate std;

use super::super::policies;
use super::*;
use crate::hal::{Memory, testing::TestingHal};
use alloc::{boxed::Box, rc::Rc};
use bitbox_secp256k1::musig::{SecretNonce, verify_partial};
use bitcoin::bip32::{Xpriv, Xpub};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use core::cell::RefCell;
use pb::btc_mu_sig2_init::Phase;
use util::bip32::HARDENED;

struct Fixture {
    init: pb::BtcSignInitRequest,
    inputs: Vec<pb::BtcSignInputRequest>,
    output: pb::BtcSignOutputRequest,
    contexts: Vec<policies::musig::SigningContext>,
    messages: Vec<[u8; 32]>,
    other_secret: [u8; 32],
    tweaks: Vec<Vec<[u8; 32]>>,
}

/// A registered MuSig wallet policy and the aggregate the fixture signs for.
struct Wallet {
    policy: &'static str,
    /// Key expression of the aggregate to sign with, always containing our @0.
    expression: &'static str,
    /// Index of the other participant of `expression`.
    other: usize,
    /// Number of keys in the policy. @0 is ours, the others are bare xpubs.
    num_keys: usize,
    /// Whether the key path has no script tree, i.e. the BIP-86 tweak applies.
    /// Only used for the exported reference transcripts.
    bip86: bool,
}

const KEY_PATH_WALLET: Wallet = Wallet {
    policy: "tr(musig(@0,@1)/**)",
    expression: "musig(@0,@1)/**",
    other: 1,
    num_keys: 2,
    bip86: true,
};

const LEAF_WALLET: Wallet = Wallet {
    policy: "tr(@0/<2;3>/*,pk(musig(@0,@1)/**))",
    expression: "musig(@0,@1)/**",
    other: 1,
    num_keys: 2,
    bip86: false,
};

async fn fixture(hal: &mut TestingHal<'_>, leaf: bool) -> Fixture {
    fixture_for(hal, if leaf { &LEAF_WALLET } else { &KEY_PATH_WALLET }).await
}

async fn fixture_for(hal: &mut TestingHal<'_>, wallet: &Wallet) -> Fixture {
    crate::keystore::testing::mock_unlocked();
    musig2::clear();
    let origin = vec![48 + HARDENED, 1 + HARDENED, HARDENED, 3 + HARDENED];
    let our_key = pb::KeyOriginInfo {
        root_fingerprint: crate::keystore::root_fingerprint().unwrap(),
        keypath: origin.clone(),
        xpub: Some(
            crate::keystore::get_xpub(hal, &origin, Compute::Once)
                .await
                .unwrap()
                .into(),
        ),
    };
    let others: Vec<_> = (1..wallet.num_keys)
        .map(|i| Xpriv::new_master(bitcoin::NetworkKind::Test, &[16 + i as u8; 32]).unwrap())
        .collect();
    let other = others[wallet.other - 1];
    let mut keys = vec![our_key];
    keys.extend(others.iter().map(|other| pb::KeyOriginInfo {
        xpub: Some(crate::bip32::Xpub::from(Xpub::from_priv(SECP256K1, other)).into()),
        ..Default::default()
    }));
    let policy = pb::btc_script_config::Policy {
        policy: wallet.policy.into(),
        keys,
    };
    let hash = policies::get_hash(pb::BtcCoin::Tbtc, &policy).unwrap();
    hal.memory
        .multisig_set_by_hash(&hash, "MuSig wallet")
        .unwrap();
    let parsed = policies::parse(hal, &policy, pb::BtcCoin::Tbtc)
        .await
        .unwrap();
    let mut inputs = Vec::new();
    let mut contexts = Vec::new();
    let mut prevouts = Vec::new();
    let mut tweaks = Vec::new();
    // Two inputs exercise piggybacked results and the same participant key with
    // distinct nonces. The second input chooses a different aggregate child.
    for index in 0..2 {
        let selector: Vec<_> = origin.iter().copied().chain([0, index]).collect();
        let context = parsed.musig_context(wallet.expression, &selector).unwrap();
        let policies::Descriptor::Tr(tr) = parsed.derive_at_keypath(&selector).unwrap() else {
            panic!()
        };
        let script =
            ScriptBuf::new_p2tr_tweaked(bitcoin::key::TweakedPublicKey::dangerous_assume_tweaked(
                bitcoin::secp256k1::XOnlyPublicKey::from_slice(&tr.output_key()).unwrap(),
            ));
        // Reconstruct the tweak sequence independently for reference interop.
        let mut aggregate_xpub = Xpub {
            network: bitcoin::NetworkKind::Main,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: 0.into(),
            public_key: bitcoin::secp256k1::PublicKey::from_slice(&context.bare_key).unwrap(),
            chain_code: hex_lit::hex!(
                "868087ca02a6f974c4598924c36b57762d32cb45717167e300622c7167e38965"
            )
            .into(),
        };
        let mut input_tweaks = Vec::new();
        for child in [0, index] {
            let child = bitcoin::bip32::ChildNumber::from_normal_idx(child).unwrap();
            input_tweaks.push(
                aggregate_xpub
                    .ckd_pub_tweak(child)
                    .unwrap()
                    .0
                    .secret_bytes(),
            );
            aggregate_xpub = aggregate_xpub.ckd_pub(SECP256K1, child).unwrap();
        }
        assert_eq!(aggregate_xpub.public_key.serialize(), context.internal_key);
        if wallet.bip86 {
            input_tweaks.push(
                bitcoin::TapTweakHash::from_key_and_tweak(
                    aggregate_xpub.public_key.x_only_public_key().0,
                    None,
                )
                .to_byte_array(),
            );
        }
        tweaks.push(input_tweaks);
        prevouts.push(TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: script,
        });
        inputs.push(pb::BtcSignInputRequest {
            prev_out_hash: vec![1 + index as u8; 32],
            prev_out_index: 0,
            prev_out_value: 100_000,
            sequence: 0xffffffff,
            keypath: selector,
            musig2: Some(pb::BtcMuSig2Input {
                key_expression: wallet.expression.into(),
                aggregate_key: context.bare_key.to_vec(),
                participant_pubkeys: context
                    .participants
                    .iter()
                    .map(|key| key.to_vec())
                    .collect(),
                context_key: context.aggregate.public_key().serialize().to_vec(),
                tapleaf_hash: context.tapleaf_hash.map(|hash| hash.to_vec()),
            }),
            ..Default::default()
        });
        contexts.push(context);
    }
    let output = pb::BtcSignOutputRequest {
        r#type: pb::BtcOutputType::P2wpkh as _,
        value: 195_000,
        payload: vec![5; 20],
        ..Default::default()
    };
    let transaction = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|input| TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_slice(&input.prev_out_hash).unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(output.value),
            script_pubkey: ScriptBuf::new_p2wpkh(
                &bitcoin::WPubkeyHash::from_slice(&output.payload).unwrap(),
            ),
        }],
    };
    let mut sighash = SighashCache::new(&transaction);
    let messages = contexts
        .iter()
        .enumerate()
        .map(|(index, context)| {
            let hash = match context.tapleaf_hash {
                Some(hash) => sighash.taproot_script_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    bitcoin::TapLeafHash::from_byte_array(hash),
                    TapSighashType::Default,
                ),
                None => sighash.taproot_key_spend_signature_hash(
                    index,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                ),
            }
            .unwrap();
            hash.to_byte_array()
        })
        .collect();
    let init = pb::BtcSignInitRequest {
        coin: pb::BtcCoin::Tbtc as _,
        version: 2,
        num_inputs: 2,
        num_outputs: 1,
        script_configs: vec![pb::BtcScriptConfigWithKeypath {
            keypath: origin,
            script_config: Some(pb::BtcScriptConfig {
                config: Some(pb::btc_script_config::Config::Policy(policy)),
            }),
        }],
        musig2: Some(pb::BtcMuSig2Init {
            phase: Phase::Nonce as _,
            session_id: vec![],
        }),
        ..Default::default()
    };
    Fixture {
        init,
        inputs,
        output,
        contexts,
        messages,
        other_secret: other.private_key.secret_bytes(),
        tweaks,
    }
}

fn next(response: Response) -> pb::BtcSignNextResponse {
    match response {
        Response::BtcSignNext(next) => next,
        Response::Btc(pb::BtcResponse {
            response: Some(pb::btc_response::Response::SignNext(next)),
        }) => next,
        _ => panic!("unexpected response"),
    }
}

async fn run(
    hal: &mut TestingHal<'_>,
    fixture: &Fixture,
    nonces: Vec<pb::BtcMuSig2NoncesRequest>,
    mutate_pass_two: bool,
) -> Result<(Vec<pb::BtcMuSig2Result>, Vec<u8>), Error> {
    let inputs = fixture.inputs.clone();
    let output = fixture.output.clone();
    let results = Rc::new(RefCell::new(Vec::new()));
    let observed = results.clone();
    let counts = RefCell::new([0; 2]);
    *crate::hww::MOCK_NEXT_REQUEST.0.borrow_mut() = Some(Box::new(move |response| {
        let next = next(response);
        assert!(!next.has_signature);
        if let Some(result) = next.musig2_result {
            observed.borrow_mut().push(result);
        }
        Ok(match NextType::try_from(next.r#type).unwrap() {
            NextType::Input => {
                let i = next.index as usize;
                counts.borrow_mut()[i] += 1;
                let mut input = inputs[i].clone();
                if mutate_pass_two && counts.borrow()[i] == 2 {
                    input.prev_out_value += 1;
                }
                Request::BtcSignInput(input)
            }
            NextType::Output => Request::BtcSignOutput(output.clone()),
            NextType::Musig2Nonces => Request::Btc(pb::BtcRequest {
                request: Some(pb::btc_request::Request::Musig2Nonces(
                    nonces[next.index as usize].clone(),
                )),
            }),
            _ => panic!("unexpected next type"),
        })
    }));
    let last = next(process(hal, &fixture.init).await?);
    assert_eq!(last.r#type, NextType::Done as i32);
    assert!(!last.has_signature);
    if let Some(result) = last.musig2_result {
        results.borrow_mut().push(result);
    }
    let results = results.borrow().clone();
    Ok((results, last.musig2_session_id))
}

#[async_test::test]
async fn test_musig2_signtx() {
    for leaf in [false, true] {
        let mut hal = TestingHal::new();
        let mut fixture = fixture(&mut hal, leaf).await;
        let (public, id) = run(&mut hal, &fixture, vec![], false).await.unwrap();
        assert_eq!(public.len(), 2);
        assert_eq!(id.len(), 32);
        let mut requests = Vec::new();
        let mut ordered = Vec::new();
        let mut peer_signatures = Vec::new();
        for (i, result) in public.iter().enumerate() {
            let ctx = &fixture.contexts[i];
            assert_eq!(result.input_index, i as u32);
            let ours = &result.public_nonce;
            assert_eq!(ours.len(), 66);
            assert!(result.partial_signature.is_empty());
            let other = SecretNonce::generate(
                &[20 + i as u8; 32],
                &fixture.other_secret,
                &ctx.aggregate,
                &fixture.messages[i],
                &[7; 32],
            )
            .unwrap();
            let nonces: Vec<[u8; 66]> = ctx
                .participants
                .iter()
                .map(|key| {
                    if key == &ctx.participant {
                        ours.as_slice().try_into().unwrap()
                    } else {
                        other.public_nonce()
                    }
                })
                .collect();
            // BIP373 is a map; nonce record order need not equal aggregation order.
            let mut records: Vec<_> = ctx
                .participants
                .iter()
                .zip(&nonces)
                .map(|(key, nonce)| pb::BtcMuSig2Nonce {
                    participant_pubkey: key.to_vec(),
                    public_nonce: nonce.to_vec(),
                })
                .collect();
            records.reverse();
            requests.push(pb::BtcMuSig2NoncesRequest {
                input_index: i as _,
                context_key: public[i].context_key.clone(),
                tapleaf_hash: public[i].tapleaf_hash.clone(),
                nonces: records,
            });
            peer_signatures.push(
                other
                    .sign(
                        &fixture.other_secret,
                        &ctx.aggregate,
                        &nonces,
                        &fixture.messages[i],
                    )
                    .unwrap(),
            );
            ordered.push(nonces);
        }
        fixture.init.musig2 = Some(pb::BtcMuSig2Init {
            phase: Phase::Sign as _,
            session_id: id,
        });
        let (partials, _) = run(&mut hal, &fixture, requests, false).await.unwrap();
        assert_eq!(partials.len(), 2);
        for i in 0..2 {
            let ctx = &fixture.contexts[i];
            let sig = &partials[i].partial_signature;
            assert!(partials[i].public_nonce.is_empty());
            assert_eq!(partials[i].input_index, i as u32);
            assert_eq!(partials[i].context_key, public[i].context_key);
            let signer = ctx
                .participants
                .iter()
                .position(|key| key == &ctx.participant)
                .unwrap();
            verify_partial(
                &ctx.aggregate,
                &ordered[i],
                &fixture.messages[i],
                signer,
                sig.as_slice().try_into().unwrap(),
            )
            .unwrap();
        }
        // Optional public-only transcript for an independent BIP327 checker.
        // No firmware or participant private key/nonce is included.
        if let Ok(directory) = std::env::var("BITBOX_MUSIG2_FIXTURES") {
            let records: Vec<_> = fixture.contexts.iter().enumerate().map(|(i, ctx)| {
                let sig = &partials[i].partial_signature;
                let signer = ctx.participants.iter().position(|key| key == &ctx.participant).unwrap();
                let mut signatures = vec![hex::encode(peer_signatures[i]); 2];
                signatures[signer] = hex::encode(sig);
                serde_json::json!({
                    "pubkeys": ctx.participants.iter().map(hex::encode).collect::<Vec<_>>(),
                    "pubnonces": ordered[i].iter().map(hex::encode).collect::<Vec<_>>(),
                    "tweaks": fixture.tweaks[i].iter().map(hex::encode).collect::<Vec<_>>(),
                    "is_xonly": if leaf { vec![false, false] } else { vec![false, false, true] },
                    "message": hex::encode(fixture.messages[i]),
                    "aggregate_key": hex::encode(ctx.aggregate.public_key().serialize()),
                    "partial_signatures": signatures,
                })
            }).collect();
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::write(
                std::path::Path::new(&directory).join(if leaf {
                    "scriptpath.json"
                } else {
                    "keypath.json"
                }),
                serde_json::to_vec_pretty(&records).unwrap(),
            )
            .unwrap();
        }
        assert_eq!(
            process(&mut hal, &fixture.init).await,
            Err(Error::InvalidState)
        );
    }
}

#[async_test::test]
async fn test_musig2_signtx_rejects_changes() {
    let mut hal = TestingHal::new();
    let mut fixture = fixture(&mut hal, false).await;
    let (_, id) = run(&mut hal, &fixture, vec![], false).await.unwrap();
    fixture.init.musig2 = Some(pb::BtcMuSig2Init {
        phase: Phase::Sign as _,
        session_id: id,
    });
    assert_eq!(
        run(&mut hal, &fixture, vec![], true).await,
        Err(Error::InvalidInput)
    );
    assert_eq!(
        process(&mut hal, &fixture.init).await,
        Err(Error::InvalidState)
    );

    fixture.init.musig2 = Some(pb::BtcMuSig2Init {
        phase: Phase::Nonce as _,
        session_id: vec![],
    });
    let (_, id) = run(&mut hal, &fixture, vec![], false).await.unwrap();
    fixture.init.musig2 = Some(pb::BtcMuSig2Init {
        phase: Phase::Sign as _,
        session_id: id,
    });
    fixture.output.value -= 1;
    assert_eq!(
        run(&mut hal, &fixture, vec![], false).await,
        Err(Error::InvalidInput)
    );
    assert_eq!(
        process(&mut hal, &fixture.init).await,
        Err(Error::InvalidState)
    );
}

#[async_test::test]
async fn test_musig2_signtx_user_abort() {
    for signing in [false, true] {
        let mut hal = TestingHal::new();
        let mut fixture = fixture(&mut hal, false).await;
        if signing {
            let (_, id) = run(&mut hal, &fixture, vec![], false).await.unwrap();
            fixture.init.musig2 = Some(pb::BtcMuSig2Init {
                phase: Phase::Sign as _,
                session_id: id,
            });
        }
        // Reject the first authorization in this round. Signing takes ownership
        // before the UI, so an aborted second round cannot be resumed.
        hal.ui = crate::hal::testing::ui::TestingUi::new();
        hal.ui.abort_nth(0);
        assert_eq!(
            run(&mut hal, &fixture, vec![], false).await,
            Err(Error::UserAbort)
        );
        if signing {
            assert_eq!(
                process(&mut hal, &fixture.init).await,
                Err(Error::InvalidState)
            );
        } else {
            hal.ui = crate::hal::testing::ui::TestingUi::new();
            run(&mut hal, &fixture, vec![], false).await.unwrap();
            musig2::clear();
        }
    }
}

/// Peer nonces and the nonces requests the host sends in a NONCE_AND_SIGN round:
/// every participant except us, as the device contributes last.
fn peer_nonces(fixture: &Fixture) -> (Vec<SecretNonce>, Vec<pb::BtcMuSig2NoncesRequest>) {
    let mut peers = Vec::new();
    let mut requests = Vec::new();
    for (i, ctx) in fixture.contexts.iter().enumerate() {
        let peer = SecretNonce::generate(
            &[30 + i as u8; 32],
            &fixture.other_secret,
            &ctx.aggregate,
            &fixture.messages[i],
            &[9; 32],
        )
        .unwrap();
        let metadata = fixture.inputs[i].musig2.as_ref().unwrap();
        requests.push(pb::BtcMuSig2NoncesRequest {
            input_index: i as _,
            context_key: metadata.context_key.clone(),
            tapleaf_hash: metadata.tapleaf_hash.clone(),
            nonces: ctx
                .participants
                .iter()
                .filter(|key| **key != ctx.participant)
                .map(|key| pb::BtcMuSig2Nonce {
                    participant_pubkey: key.to_vec(),
                    public_nonce: peer.public_nonce().to_vec(),
                })
                .collect(),
        });
        peers.push(peer);
    }
    (peers, requests)
}

/// Run a NONCE_AND_SIGN round for the wallet and verify every contribution as the
/// host would, then complete the signature with the peer.
async fn check_nonce_and_sign(wallet: &Wallet) {
    let mut hal = TestingHal::new();
    let mut fixture = fixture_for(&mut hal, wallet).await;
    fixture.init.musig2 = Some(pb::BtcMuSig2Init {
        phase: Phase::NonceAndSign as _,
        session_id: vec![],
    });
    let (peers, requests) = peer_nonces(&fixture);
    let (results, id) = run(&mut hal, &fixture, requests.clone(), false)
        .await
        .unwrap();
    assert_eq!(id.len(), 32);
    assert_eq!(results.len(), 2);
    for (i, peer) in peers.into_iter().enumerate() {
        let ctx = &fixture.contexts[i];
        let result = &results[i];
        assert_eq!(result.input_index, i as u32);
        assert_eq!(result.participant_pubkey, ctx.participant.to_vec());
        assert_eq!(result.public_nonce.len(), 66);
        assert_eq!(result.partial_signature.len(), 32);
        let nonces: Vec<[u8; 66]> = ctx
            .participants
            .iter()
            .map(|key| {
                if key == &ctx.participant {
                    result.public_nonce.as_slice().try_into().unwrap()
                } else {
                    peer.public_nonce()
                }
            })
            .collect();
        let signer = ctx
            .participants
            .iter()
            .position(|key| key == &ctx.participant)
            .unwrap();
        verify_partial(
            &ctx.aggregate,
            &nonces,
            &fixture.messages[i],
            signer,
            result.partial_signature.as_slice().try_into().unwrap(),
        )
        .unwrap();
        // The peer, which contributed its nonce first, can finish the session.
        peer.sign(
            &fixture.other_secret,
            &ctx.aggregate,
            &nonces,
            &fixture.messages[i],
        )
        .unwrap();
    }

    // Nothing was retained: the handle cannot be used to sign, and the same
    // transaction can be signed again in a fresh single round.
    let mut signing = fixture.init.clone();
    signing.musig2 = Some(pb::BtcMuSig2Init {
        phase: Phase::Sign as _,
        session_id: id,
    });
    assert_eq!(process(&mut hal, &signing).await, Err(Error::InvalidState));
    run(&mut hal, &fixture, requests, false).await.unwrap();
}

#[async_test::test]
async fn test_musig2_signtx_nonce_and_sign() {
    check_nonce_and_sign(&KEY_PATH_WALLET).await;
    check_nonce_and_sign(&LEAF_WALLET).await;
}

#[async_test::test]
async fn test_musig2_signtx_nonce_and_sign_2of3() {
    // Our key is part of two aggregates, the key path and one leaf. Each is a
    // distinct session, and only the requested expression is signed.
    const POLICY: &str = "tr(musig(@0,@1)/**,{pk(musig(@0,@2)/**),pk(musig(@1,@2)/**)})";
    for (expression, other, bip86) in [("musig(@0,@1)/**", 1, false), ("musig(@0,@2)/**", 2, false)]
    {
        check_nonce_and_sign(&Wallet {
            policy: POLICY,
            expression,
            other,
            num_keys: 3,
            bip86,
        })
        .await;
    }
}

#[async_test::test]
async fn test_musig2_signtx_nonce_and_sign_rejects_bad_nonces() {
    for mutation in 0..3 {
        let mut hal = TestingHal::new();
        let mut fixture = fixture(&mut hal, false).await;
        fixture.init.musig2 = Some(pb::BtcMuSig2Init {
            phase: Phase::NonceAndSign as _,
            session_id: vec![],
        });
        let (_, mut requests) = peer_nonces(&fixture);
        let ctx = &fixture.contexts[0];
        match mutation {
            // Our own nonce must not be supplied by the host.
            0 => {
                let public_nonce = requests[0].nonces[0].public_nonce.clone();
                requests[0].nonces.push(pb::BtcMuSig2Nonce {
                    participant_pubkey: ctx.participant.to_vec(),
                    public_nonce,
                })
            }
            // Every other participant's nonce is required.
            1 => requests[0].nonces.clear(),
            // A nonce for someone other than the peer is rejected.
            _ => requests[0].nonces[0].participant_pubkey[1] ^= 1,
        }
        assert_eq!(
            run(&mut hal, &fixture, requests, false).await,
            Err(Error::InvalidInput)
        );
    }
}

#[async_test::test]
async fn test_musig2_signtx_nonce_and_sign_keeps_pending_session() {
    // A retained nonce round of another session is neither needed nor touched.
    let mut hal = TestingHal::new();
    let mut fixture = fixture(&mut hal, false).await;
    let (public, pending) = run(&mut hal, &fixture, vec![], false).await.unwrap();

    let nonce_round = fixture.init.clone();
    fixture.init.musig2 = Some(pb::BtcMuSig2Init {
        phase: Phase::NonceAndSign as _,
        session_id: vec![],
    });
    let (peers, requests) = peer_nonces(&fixture);
    run(&mut hal, &fixture, requests, false).await.unwrap();

    // A session ID is never accepted for NONCE_AND_SIGN.
    fixture.init.musig2.as_mut().unwrap().session_id = pending.clone();
    assert_eq!(
        process(&mut hal, &fixture.init).await,
        Err(Error::InvalidInput)
    );

    // The pending session survived and completes with all participants' nonces.
    fixture.init = nonce_round;
    fixture.init.musig2 = Some(pb::BtcMuSig2Init {
        phase: Phase::Sign as _,
        session_id: pending,
    });
    let requests = fixture
        .contexts
        .iter()
        .enumerate()
        .map(|(i, ctx)| pb::BtcMuSig2NoncesRequest {
            input_index: i as _,
            context_key: public[i].context_key.clone(),
            tapleaf_hash: public[i].tapleaf_hash.clone(),
            nonces: ctx
                .participants
                .iter()
                .map(|key| pb::BtcMuSig2Nonce {
                    participant_pubkey: key.to_vec(),
                    public_nonce: if key == &ctx.participant {
                        public[i].public_nonce.clone()
                    } else {
                        peers[i].public_nonce().to_vec()
                    },
                })
                .collect(),
        })
        .collect();
    let (partials, _) = run(&mut hal, &fixture, requests, false).await.unwrap();
    assert_eq!(partials.len(), 2);
    assert!(partials.iter().all(|p| p.partial_signature.len() == 32));
}
