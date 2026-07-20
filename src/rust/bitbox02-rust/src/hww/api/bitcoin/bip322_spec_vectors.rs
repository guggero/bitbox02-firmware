// SPDX-License-Identifier: Apache-2.0

//! BIP-322 spec conformance tests, generated from the official test vectors
//! (bip-0322/generated-test-vectors.json in the bips repository) by
//! tools/gen-bip322-spec-vectors.py. Do not edit by hand.
//!
//! Each vector's known-good signature is verified against the sighash computed by the
//! `bip322` module: if our `to_spend`/`to_sign` construction or sighash computation deviated
//! from the spec in any way, signature verification would fail.
//!
//! The `proof_of_funds` vectors are not included: multi-input (proof-of-funds) signing is
//! deliberately rejected by `bip322::validate_init` until it is implemented. The `error`
//! vectors exercise verifier behavior and do not apply to a signer; the signer-side
//! equivalents are covered by the `validate_*` tests in the `bip322` module.

use super::bip322::{self, SighashMode};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey, ecdsa, schnorr};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Amount, ScriptBuf, TapLeafHash, TxOut};
use hex_lit::hex;

enum Check {
    /// ECDSA signature(s): each must verify against a distinct one of the given pubkeys.
    Ecdsa {
        mode: Mode,
        script_code: &'static [u8],
        pubkeys: &'static [&'static [u8]],
        sigs_der: &'static [&'static [u8]],
    },
    /// Taproot key-path spend: 64-byte schnorr signature against the output key.
    SchnorrKeyPath {
        output_key: &'static [u8],
        sig: &'static [u8],
    },
    /// Taproot script-path spend: schnorr signature against one of the keys in the leaf
    /// script (which key depends on the executed branch; a wrong sighash fails against all).
    SchnorrScriptPath {
        leaf_script: &'static [u8],
        xonly_key_candidates: &'static [&'static [u8]],
        sig: &'static [u8],
    },
}

enum Mode {
    SegwitV0,
    Legacy,
}

struct SpecVector {
    name: &'static str,
    message: &'static [u8],
    script_pubkey: &'static [u8],
    version: u32,
    locktime: u32,
    sequence: u32,
    check: Check,
}

static SPEC_VECTORS: &[SpecVector] = &[
    SpecVector {
        name: "simple_p2wpkh",
        message: b"2V6TUTMSH4VQ3Z7WZWKYD7DFNH",
        script_pubkey: &hex!("001402ef97dc47b7cc57e7d05a750be3f78300da7c85"),
        version: 0,
        locktime: 0,
        sequence: 0,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!("76a91402ef97dc47b7cc57e7d05a750be3f78300da7c8588ac"),
            pubkeys: &[&hex!(
                "02a6e7aeeca8ebbee4b508e2a3b5ce7213b7c39d4387d01b4559e085ae63b4d7d3"
            )],
            sigs_der: &[&hex!(
                "3045022100b0ba85d7f1372d67e3977b5174ac91105d7d95b4025db9f44d640cca62a5d6240220093df66a6fe5aead9b9fd5aa54e71784e8882e8bd76fb79b628502c3bf1958d4"
            )],
        },
    },
    SpecVector {
        name: "simple_p2tr",
        message: b"PURVOQ544B6HUATVBJZN5EZJUU",
        script_pubkey: &hex!(
            "5120c038cb8c0c783475d76fba41a5866f7e80385898f10609855c20d2aced117127"
        ),
        version: 0,
        locktime: 0,
        sequence: 0,
        check: Check::SchnorrKeyPath {
            output_key: &hex!("c038cb8c0c783475d76fba41a5866f7e80385898f10609855c20d2aced117127"),
            sig: &hex!(
                "7a07645bba9cee6bc2d3408174eb9d7ac3397e7302b2d5b7bc460a225b4ae2c9774ac1ee864f3ff91e76f7ee6ebba49c0828287e0f98c3b9e1ba2a9bd8a66bbc"
            ),
        },
    },
    SpecVector {
        name: "simple_p2wsh_multisig_2of2",
        message: b"G7ZTXXOVJFHGDD6XYJAGBAMT5A",
        script_pubkey: &hex!(
            "00207690f1a061e1992ae5b672d820ed71c536f3eee13cf968ec76ae47c4b3f81069"
        ),
        version: 0,
        locktime: 0,
        sequence: 0,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!(
                "5221036cbbf3b066eac7bc9328889a120269821cba2a21ce566e587eade93eeeb84048210281856452ca5e031c117cceafe0644184dfe01b14dfa4fa99b8e9412186714c9652ae"
            ),
            pubkeys: &[
                &hex!("036cbbf3b066eac7bc9328889a120269821cba2a21ce566e587eade93eeeb84048"),
                &hex!("0281856452ca5e031c117cceafe0644184dfe01b14dfa4fa99b8e9412186714c96"),
            ],
            sigs_der: &[
                &hex!(
                    "30450221008a9757fd0a3dba9347c5584e3cf8ee226e160960fcad6c365625169a1bd0726f022009b93edc15625a4a6ebb6448fb8d5dc2d950fe6ff4d46f3ad294c50b30c57e89"
                ),
                &hex!(
                    "3045022100d0eefb0c9b1a33b20ef87b74eaca77ba6cd707ae0234d3b07f68ac66e3df766c0220696080ec114a45ecaa53e113580c75de617fbc9c2f7dceadfaebe2ffd79cc192"
                ),
            ],
        },
    },
    SpecVector {
        name: "simple_p2wsh_multisig_3of3",
        message: b"Z3SB7SRL555ZGOHVMYT5WG7RIZ",
        script_pubkey: &hex!(
            "0020e8afbbbbe581912dba6d2eaf72ab5089a9f7e13aa909abb093d0370ac4e6a51e"
        ),
        version: 0,
        locktime: 0,
        sequence: 0,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!(
                "532102a8d34dd98e3f4983f913eec380edc4dd20a9b3b2b218040b8f77d863f0566e1c2102e8175a94cb706e3731daf26355e96fec1266974ad8ed0e737be3d67a7ead6f9b21032b697ab95806cebdb5b9fceadde920da97cb4373b6d2992a2e98f17f944905da53ae"
            ),
            pubkeys: &[
                &hex!("02a8d34dd98e3f4983f913eec380edc4dd20a9b3b2b218040b8f77d863f0566e1c"),
                &hex!("02e8175a94cb706e3731daf26355e96fec1266974ad8ed0e737be3d67a7ead6f9b"),
                &hex!("032b697ab95806cebdb5b9fceadde920da97cb4373b6d2992a2e98f17f944905da"),
            ],
            sigs_der: &[
                &hex!(
                    "304402202348e87e9bf9509957d6761fa116e613eb1356ee0ba489bb2da58d236642519f0220126e6e54ac0f0a1fa4f017a7afc7b08e57e8b6eee6e2ab6bfd4f22d83ce3bade"
                ),
                &hex!(
                    "30450221008c3859c96e0d2ccbcf06eb05178efe6cb635607ef02890ea205ac8ac7640279402201137c1c3b909848485bbdbc8a2615c105ff536c37a7348772a335ca6634066d3"
                ),
                &hex!(
                    "3045022100fe5514fb005e037a6bb7cbc746971037beb739867c2fad437cdd1023f8241e9302201daa1f08285cd4c7d2c76a780303d9a87b7524e27b66df95ac7743723f1a26d0"
                ),
            ],
        },
    },
    SpecVector {
        name: "full_p2pkh",
        message: b"MOISC5NCQ42ADH2SUXLELUJOWH",
        script_pubkey: &hex!("76a914200ce62eec15e58dbfa4a18d38131e2996011fa688ac"),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::Ecdsa {
            mode: Mode::Legacy,
            script_code: &hex!("76a914200ce62eec15e58dbfa4a18d38131e2996011fa688ac"),
            pubkeys: &[&hex!(
                "025c3cada1f5263e2a2d68bacb2f1e731d14084982c60114f97eacd70cbfd3f544"
            )],
            sigs_der: &[&hex!(
                "304402207ef2dfed9bc266eb362ff491996559405239aa83b660948037f54f9b8a6f042902200efdc4e5c1ce6a037ec5880ddd94234d8940269fd6cac970256b853f54e63372"
            )],
        },
    },
    SpecVector {
        name: "full_p2wpkh",
        message: b"KLE5MMJBTNF4AVZXIO3GIL5UWF",
        script_pubkey: &hex!("00141817f16007d1e8f20910200b0843ae32806f9a84"),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!("76a9141817f16007d1e8f20910200b0843ae32806f9a8488ac"),
            pubkeys: &[&hex!(
                "0332eae70f3bdcd330015305700800df197a03c7f3374909d8b7b7b72070e85373"
            )],
            sigs_der: &[&hex!(
                "30450221008d88fce73ca140a6bd0db30ed2b783c1d864370289905deadaa15c8a35c380c502200690ef9b377f0aab09e608509ba02ef871645c50215aae18df74bc82825b740b"
            )],
        },
    },
    SpecVector {
        name: "full_p2tr",
        message: b"XQMVC3YR6AOGZIHLSUQ2NSSBI2",
        script_pubkey: &hex!(
            "5120664fe847eafe592ddf2b10d49299990c48ad68cb23ef3ca76461d7636239a821"
        ),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::SchnorrKeyPath {
            output_key: &hex!("664fe847eafe592ddf2b10d49299990c48ad68cb23ef3ca76461d7636239a821"),
            sig: &hex!(
                "d45d2cea395d9634481a80b0b64daffcf706aae6a373b1567edee2d0ff38e0f81fd53f2f5ba7ab9366773f92d70ed21edb78e9b1709ddf319d155a9fc0687c57"
            ),
        },
    },
    SpecVector {
        name: "full_p2tr_time_lock",
        message: b"AY2VOQOXYI5CN2EHZKLOX7ZI37",
        script_pubkey: &hex!(
            "5120d3129b1bccc13221c81e0a0a00364cf336becd37b1f96742758133276fa3ddcc"
        ),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::SchnorrScriptPath {
            leaf_script: &hex!(
                "6320ad87d784e921d02bf0b89a41f8eded6a5d8409f3b4bfb935fc0e0f4e519c42206702e007b275202632e7e2d979cad802f02353c884d79a0e2bc7d72dc4f79dc1130f101bdfa14068ac"
            ),
            xonly_key_candidates: &[
                &hex!("ad87d784e921d02bf0b89a41f8eded6a5d8409f3b4bfb935fc0e0f4e519c4220"),
                &hex!("2632e7e2d979cad802f02353c884d79a0e2bc7d72dc4f79dc1130f101bdfa140"),
            ],
            sig: &hex!(
                "fbee4f47a7606c2c69bda5b0f654d14dce7119069e0fa8fcf02de1053695cf211bb9535267e592dd13a3e7a88a9bf6be9b5fd139463810ac294e7113791729c3"
            ),
        },
    },
    SpecVector {
        name: "full_p2sh_p2wpkh",
        message: b"EMYGZHEY3LIANYKCR7XJF3NMFQ",
        script_pubkey: &hex!("a91408ad02e25134a49a5b8eaf355bb6d80e0ec3286087"),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!("76a914b2fe1a431ff28b022e31db94e66f651a3b5c6d5988ac"),
            pubkeys: &[&hex!(
                "02c8de0c4a165fc86f102f00ffaf76c8642c3e1e8904ef197f86884c442c280709"
            )],
            sigs_der: &[&hex!(
                "3044022031257aa6f49f5479736d531a45915cd15a7bdf306f023440eca1fd8991b905f502201cbf5321c93ccf395819d55230baed2d0f1ad52541caf2584e50e5e9b199c6c3"
            )],
        },
    },
    SpecVector {
        name: "full_p2wsh_time_lock",
        message: b"MGKMA2MJUBDHT55J7MHOLM7UPE",
        script_pubkey: &hex!(
            "0020b831b77b8d7c5806e621ceae2ecba4fdf98dffab1db0258833b1d81432e82b44"
        ),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!(
                "632103ad87d784e921d02bf0b89a41f8eded6a5d8409f3b4bfb935fc0e0f4e519c42206702e007b275210386461afa1d2a0a9e83f6587df9ba9a268a686e7b5640928e6991a6b09afae97268ac"
            ),
            pubkeys: &[
                &hex!("03ad87d784e921d02bf0b89a41f8eded6a5d8409f3b4bfb935fc0e0f4e519c4220"),
                &hex!("0386461afa1d2a0a9e83f6587df9ba9a268a686e7b5640928e6991a6b09afae972"),
            ],
            sigs_der: &[&hex!(
                "3045022100eb83300f61e42633cb3c0736bb989ae997700953b7a24cd5a863c45e7b89199402204dbb04638141377027633f59db26ea7155ba7a9a8fec590521bf83feb814c6ed"
            )],
        },
    },
    SpecVector {
        name: "full_p2wsh_multisig_2of2",
        message: b"QXYOWYWO7ZGJC4OPNC367HBUQF",
        script_pubkey: &hex!(
            "002041c71c7ebe18c7ea35cc1fa57137960af289ec0763e7b935526cea067f020597"
        ),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!(
                "52210244f7cb842a4ce4f352ce4062ae5e0a5d60d6faa0b07b62c2063484aa5297bbce210234eed6190efc47716b953a050b563f8b2b523addea955ae43351dd2a92aa49f452ae"
            ),
            pubkeys: &[
                &hex!("0244f7cb842a4ce4f352ce4062ae5e0a5d60d6faa0b07b62c2063484aa5297bbce"),
                &hex!("0234eed6190efc47716b953a050b563f8b2b523addea955ae43351dd2a92aa49f4"),
            ],
            sigs_der: &[
                &hex!(
                    "30450221008f6e3b1bea981574a6574ea0a5a7498863a1b3613f817e8313b442539d1adc4502205139c36bb8b8a0644e258f50c9121f321aba92d3431e5b8eb710eefc4ec69116"
                ),
                &hex!(
                    "304502210080848a98b94e300c0d8062c53e403572b9c1f84e6fcd4833f6fadc723cc2849002207ee1a54a1ee77316f6c95dd2dda385e6ec071aab48663a776f81d6d1ddf911c9"
                ),
            ],
        },
    },
    SpecVector {
        name: "full_p2wsh_multisig_3of3",
        message: b"3VJANNKSXPLND6YRKG6CUEUZXX",
        script_pubkey: &hex!(
            "00203b09a95d393e3afe0f8c1d7a0b4adea3428a6e2f1cddd5a34fe5c9d7bdb7f901"
        ),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!(
                "5321022506f12c84db93ed3e896b4d58807b341b7d5eb51d79a11763836249b3a1dfe4210305b153afc370cd8f2e522e6a435cf5e9726376bf556752c1a43704956af22305210242f20cbe0540cbe3d1323cf61659f236b89c2ae593ddb7e42080597994d216e053ae"
            ),
            pubkeys: &[
                &hex!("022506f12c84db93ed3e896b4d58807b341b7d5eb51d79a11763836249b3a1dfe4"),
                &hex!("0305b153afc370cd8f2e522e6a435cf5e9726376bf556752c1a43704956af22305"),
                &hex!("0242f20cbe0540cbe3d1323cf61659f236b89c2ae593ddb7e42080597994d216e0"),
            ],
            sigs_der: &[
                &hex!(
                    "3045022100a052c3be201e5c76ef6cb8473c94fdaa7b88d3b9ae607a5d78013b2dd0b1cfc40220549d2ac5fd786fbaf0308bf98c99ed090e9b82be5fa867d0b87f71fc39e99708"
                ),
                &hex!(
                    "3045022100cadf01f497602f279159f76dd9309918d73d0c061d4d79ef708caeed571173e60220742d57043fc87413edc75c66caf48585b20996f9f3f7c7cf4e6e742ba29a5e91"
                ),
                &hex!(
                    "3045022100c8fde75d3cd7ad39b3ab9e31f23018d361111f270463362a4fd7294537845a0e02207c519377b7a0faccf68099f31720350de5461c9cf86d2a743225eaa6bc48de00"
                ),
            ],
        },
    },
    SpecVector {
        name: "full_p2sh_p2wsh_multisig_2of2",
        message: b"NQVRV3DJYLKBANM3OPTNBULEU3",
        script_pubkey: &hex!("a914ecb2eb00f12ecbf8d401f645e537187afb492c3287"),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::Ecdsa {
            mode: Mode::SegwitV0,
            script_code: &hex!(
                "522103fb824153fc000a213c5456d01780d1f292a0cfbfbc5f6f8f1dc713706c5519d12103db88ce9fb8081e50460beb37539741b0667d6f2439dd1ca283d63182421c10b152ae"
            ),
            pubkeys: &[
                &hex!("03fb824153fc000a213c5456d01780d1f292a0cfbfbc5f6f8f1dc713706c5519d1"),
                &hex!("03db88ce9fb8081e50460beb37539741b0667d6f2439dd1ca283d63182421c10b1"),
            ],
            sigs_der: &[
                &hex!(
                    "3045022100e3b60ae577881813100bd6c27d66fe2087e2ac85a5a80cd055ce84fe58013d9202200d24fc43b6b77621aa6611e567575011a003347e22a819e7f9b1be3fb85280d3"
                ),
                &hex!(
                    "3045022100f088559092a0868e8d8f41cd8217584bdb8693a5e0947cf29ff1615a1939b77a022003c895cdaa90e0fcb736be23d7d783767748d07448da998e129a253b18d6c83a"
                ),
            ],
        },
    },
    SpecVector {
        name: "full_p2sh_multisig_2of2",
        message: b"7OKFLKRXSP6J42VQOMSG7MVXEP",
        script_pubkey: &hex!("a914e97f774416226f1cb9cc9d1f6ffd004f8991252c87"),
        version: 2,
        locktime: 2016,
        sequence: 2016,
        check: Check::Ecdsa {
            mode: Mode::Legacy,
            script_code: &hex!(
                "52210384a8dc6ff3efd7fec062eb73397c2079cd3cc300ff57088f9b9f0b734c63a21821021c9c8e9c1d06e3f7de8ad05c01f5080b2b81292eb29c4cdbe14f43838256141652ae"
            ),
            pubkeys: &[
                &hex!("0384a8dc6ff3efd7fec062eb73397c2079cd3cc300ff57088f9b9f0b734c63a218"),
                &hex!("021c9c8e9c1d06e3f7de8ad05c01f5080b2b81292eb29c4cdbe14f438382561416"),
            ],
            sigs_der: &[
                &hex!(
                    "304402204faadc7f1802986e9bdc3a73355e941b48e209019c946f6c7e24a9578e470d730220682daa3141b89eeb6e2f9c8271b44d988a65ac4c934288fa041dd291c97c4602"
                ),
                &hex!(
                    "3045022100d0af08b8c632e64ccc7fa708490d856851e394fa41160c2e29fcbada6e17daf50220538c6d8d2e392b7bb79cf873e0f145212b58cbd6f82aed82a3ab944ebfe874ec"
                ),
            ],
        },
    },
];

#[test]
fn test_spec_vectors() {
    let secp = Secp256k1::verification_only();
    for vector in SPEC_VECTORS {
        match &vector.check {
            Check::Ecdsa {
                mode,
                script_code,
                pubkeys,
                sigs_der,
            } => {
                let sighash = bip322::sighash(
                    vector.message,
                    vector.script_pubkey,
                    vector.version,
                    vector.locktime,
                    vector.sequence,
                    match mode {
                        Mode::SegwitV0 => SighashMode::SegwitV0 { script_code },
                        Mode::Legacy => SighashMode::Legacy { script_code },
                    },
                )
                .unwrap();
                let msg = Message::from_digest(sighash);
                // Every signature must verify against a distinct pubkey (multisig order).
                let mut used = alloc::vec![false; pubkeys.len()];
                for sig_der in sigs_der.iter() {
                    let sig = ecdsa::Signature::from_der(sig_der).unwrap();
                    let found = pubkeys.iter().enumerate().find(|(i, pk)| {
                        !used[*i]
                            && secp
                                .verify_ecdsa(&msg, &sig, &PublicKey::from_slice(pk).unwrap())
                                .is_ok()
                    });
                    let (i, _) = found.unwrap_or_else(|| {
                        panic!("{}: signature did not verify under any key", vector.name)
                    });
                    used[i] = true;
                }
            }
            Check::SchnorrKeyPath { output_key, sig } => {
                let sighash = bip322::sighash(
                    vector.message,
                    vector.script_pubkey,
                    vector.version,
                    vector.locktime,
                    vector.sequence,
                    SighashMode::Taproot,
                )
                .unwrap();
                let msg = Message::from_digest(sighash);
                let sig = schnorr::Signature::from_slice(sig).unwrap();
                let key = XOnlyPublicKey::from_slice(output_key).unwrap();
                secp.verify_schnorr(&sig, &msg, &key)
                    .unwrap_or_else(|_| panic!("{}: schnorr verification failed", vector.name));
            }
            Check::SchnorrScriptPath {
                leaf_script,
                xonly_key_candidates,
                sig,
            } => {
                // The script-path sighash is not computed by the bip322 module (the firmware
                // signs BIP-322 taproot via key path or via the signtx policy flow); compute
                // it here from the module's to_sign transaction to validate the transaction
                // construction against the vector.
                let to_sign = bip322::create_to_sign_tx(
                    vector.message,
                    vector.script_pubkey,
                    vector.version,
                    vector.locktime,
                    vector.sequence,
                )
                .unwrap();
                let prevout = TxOut {
                    value: Amount::ZERO,
                    script_pubkey: ScriptBuf::from_bytes(vector.script_pubkey.to_vec()),
                };
                let leaf_hash = TapLeafHash::from_script(
                    bitcoin::Script::from_bytes(leaf_script),
                    bitcoin::taproot::LeafVersion::TapScript,
                );
                let sighash = SighashCache::new(&to_sign)
                    .taproot_script_spend_signature_hash(
                        0,
                        &Prevouts::All(&[prevout]),
                        leaf_hash,
                        TapSighashType::Default,
                    )
                    .unwrap();
                let msg = Message::from_digest(sighash.to_byte_array());
                let sig = schnorr::Signature::from_slice(sig).unwrap();
                let verified = xonly_key_candidates.iter().any(|key| {
                    secp.verify_schnorr(&sig, &msg, &XOnlyPublicKey::from_slice(key).unwrap())
                        .is_ok()
                });
                assert!(
                    verified,
                    "{}: schnorr verification failed against all leaf keys",
                    vector.name
                );
            }
        }
    }
}
