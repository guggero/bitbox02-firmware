#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate Rust test data for the BIP-322 spec test vectors.

Reads bip-0322/generated-test-vectors.json (from the bips repository) and emits
src/rust/bitbox02-rust/src/hww/api/bitcoin/bip322_spec_vectors.rs, which verifies the
signatures of every signable vector against the sighashes computed by the bip322 module.

Usage: gen-bip322-spec-vectors.py <generated-test-vectors.json> <output.rs>
"""

import base64
import hashlib
import io
import json
import struct
import sys

# --- address decoding (stdlib only) -----------------------------------------

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58check_decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58_ALPHABET.index(c)
    data = n.to_bytes((n.bit_length() + 7) // 8, "big")
    # leading '1's are leading zero bytes
    pad = len(s) - len(s.lstrip("1"))
    data = b"\x00" * pad + data
    payload, checksum = data[:-4], data[-4:]
    assert sha256d(payload)[:4] == checksum, "bad base58 checksum"
    return payload


def bech32_polymod(values):
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= GEN[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_decode(addr: str):
    addr = addr.lower()
    pos = addr.rfind("1")
    hrp, data = addr[:pos], [BECH32_CHARSET.index(c) for c in addr[pos + 1 :]]
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    witver = data[0]
    # BIP-173 for v0, BIP-350 (bech32m) for v1+
    expected = 1 if witver == 0 else 0x2BC830A3
    assert const == expected, f"bad bech32 checksum for {addr}"
    # convert 5-bit groups (excluding version and checksum) to bytes
    bits = 0
    acc = 0
    out = bytearray()
    for value in data[1:-6]:
        acc = (acc << 5) | value
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return witver, bytes(out)


def address_to_script_pubkey(addr: str) -> bytes:
    if addr.startswith(("bc1", "tb1")):
        witver, prog = bech32_decode(addr)
        opver = 0x00 if witver == 0 else 0x50 + witver
        return bytes([opver, len(prog)]) + prog
    payload = b58check_decode(addr)
    version, h = payload[0], payload[1:]
    assert len(h) == 20
    if version == 0x00:  # P2PKH
        return b"\x76\xa9\x14" + h + b"\x88\xac"
    if version == 0x05:  # P2SH
        return b"\xa9\x14" + h + b"\x87"
    raise ValueError(f"unknown address version {version}")


# --- transaction / witness parsing ------------------------------------------


def read_varint(f) -> int:
    (b,) = f.read(1)
    if b < 0xFD:
        return b
    if b == 0xFD:
        return struct.unpack("<H", f.read(2))[0]
    if b == 0xFE:
        return struct.unpack("<I", f.read(4))[0]
    return struct.unpack("<Q", f.read(8))[0]


def parse_witness_stack(raw: bytes):
    f = io.BytesIO(raw)
    items = [f.read(read_varint(f)) for _ in range(read_varint(f))]
    assert f.read() == b"", "trailing data after witness stack"
    return items


def parse_tx(raw: bytes):
    f = io.BytesIO(raw)
    version = struct.unpack("<i", f.read(4))[0]
    n_in = read_varint(f)
    segwit = False
    if n_in == 0:  # segwit marker
        assert f.read(1) == b"\x01"
        segwit = True
        n_in = read_varint(f)
    vin = []
    for _ in range(n_in):
        prevout = f.read(36)
        script_sig = f.read(read_varint(f))
        sequence = struct.unpack("<I", f.read(4))[0]
        vin.append({"prevout": prevout, "script_sig": script_sig, "sequence": sequence})
    n_out = read_varint(f)
    for _ in range(n_out):
        f.read(8)
        f.read(read_varint(f))
    if segwit:
        for txin in vin:
            txin["witness"] = [f.read(read_varint(f)) for _ in range(read_varint(f))]
    locktime = struct.unpack("<I", f.read(4))[0]
    assert f.read() == b"", "trailing data after tx"
    return {"version": version, "locktime": locktime, "vin": vin}


def parse_script_pushes(script: bytes):
    """Parse a script consisting only of data pushes (and OP_0)."""
    f = io.BytesIO(script)
    pushes = []
    while True:
        op = f.read(1)
        if not op:
            return pushes
        op = op[0]
        if op == 0x00:
            pushes.append(b"")
        elif op <= 0x4B:
            pushes.append(f.read(op))
        elif op == 0x4C:
            pushes.append(f.read(f.read(1)[0]))
        else:
            raise ValueError(f"unexpected opcode 0x{op:02x} in push-only script")


def multisig_keys(script: bytes):
    """Extract the 33-byte pubkeys from an OP_m <keys...> OP_n OP_CHECKMULTISIG script."""
    assert 0x51 <= script[0] <= 0x60, "expected OP_m"
    assert script[-1] == 0xAE, "expected OP_CHECKMULTISIG"
    keys = []
    i = 1
    while i < len(script) - 2:
        assert script[i] == 33, f"expected 33-byte key push at {i}"
        keys.append(script[i + 1 : i + 34])
        i += 34
    return keys


def compressed_key_pushes(script: bytes):
    """Extract all 33-byte pushes (compressed pubkey candidates) from a script."""
    keys = []
    i = 0
    while i < len(script):
        if script[i] == 0x21 and i + 34 <= len(script):
            keys.append(script[i + 1 : i + 34])
            i += 34
        else:
            i += 1
    assert keys, "no compressed key candidates found in script"
    return keys


def tapscript_xonly_keys(script: bytes):
    """Extract all 32-byte pushes (x-only key candidates) from a tapscript."""
    keys = []
    i = 0
    while i < len(script):
        if script[i] == 0x20 and i + 33 <= len(script):
            keys.append(script[i + 1 : i + 33])
            i += 33
        else:
            i += 1
    assert keys, "no x-only key candidates found in tapscript"
    return keys


# --- vector conversion -------------------------------------------------------


def split_ecdsa_sig(sig: bytes):
    assert sig[-1] == 0x01, f"expected SIGHASH_ALL byte, got {sig[-1]:#x}"
    return sig[:-1]


def convert(vector, kind):
    vtype = vector["type"]
    message = vector["message"].encode()
    spk = address_to_script_pubkey(vector["address"])
    sig_str = vector["bip322_signatures"][0]

    if kind == "simple":
        assert sig_str.startswith("smp")
        witness = parse_witness_stack(base64.b64decode(sig_str[3:]))
        script_sig = b""
        version, locktime, sequence = 0, 0, 0
    else:
        assert sig_str.startswith("ful")
        tx = parse_tx(base64.b64decode(sig_str[3:]))
        assert len(tx["vin"]) == 1
        txin = tx["vin"][0]
        witness = txin.get("witness", [])
        script_sig = txin["script_sig"]
        version, locktime, sequence = tx["version"], tx["locktime"], txin["sequence"]
        assert version == vector["tx_version"], "tx version mismatch vs json"
        assert locktime == vector["lock_time"], "locktime mismatch vs json"
        assert sequence == vector["sequence"], "sequence mismatch vs json"

    name = f"{kind}_{vtype.replace('-', '_')}"

    if vtype in ("p2wpkh", "p2sh-p2wpkh"):
        if vtype == "p2wpkh":
            key_hash = spk[2:22]
        else:
            redeem = parse_script_pushes(script_sig)[0]
            assert redeem[:2] == b"\x00\x14"
            assert (
                hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest()
                == spk[2:22]
            )
            key_hash = redeem[2:22]
        script_code = b"\x76\xa9\x14" + key_hash + b"\x88\xac"
        sig, pubkey = split_ecdsa_sig(witness[0]), witness[1]
        return dict(
            name=name,
            message=message,
            spk=spk,
            ver=version,
            lt=locktime,
            seq=sequence,
            check=("ecdsa", "SegwitV0", script_code, [pubkey], [sig]),
        )

    if vtype in (
        "p2wsh-multisig-2of2",
        "p2wsh-multisig-3of3",
        "p2sh-p2wsh-multisig-2of2",
        "p2wsh-time-lock",
    ):
        witness_script = witness[-1]
        if vtype.startswith("p2wsh"):
            assert hashlib.sha256(witness_script).digest() == spk[2:34]
        else:
            redeem = parse_script_pushes(script_sig)[0]
            assert redeem == b"\x00\x20" + hashlib.sha256(witness_script).digest()
            assert (
                hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest()
                == spk[2:22]
            )
        if "multisig" in vtype:
            keys = multisig_keys(witness_script)
            assert witness[0] == b"", "expected OP_0 dummy for CHECKMULTISIG"
            sigs = [split_ecdsa_sig(s) for s in witness[1:-1]]
        else:
            # Time-lock script (e.g. OP_IF <key1> OP_ELSE <delay> OP_CSV OP_DROP <key2>
            # OP_ENDIF OP_CHECKSIG): candidate keys are all 33-byte pushes; the signatures are
            # the DER-looking stack items (other items, like an empty IF-branch selector, only
            # affect script execution, not the sighash).
            keys = compressed_key_pushes(witness_script)
            sigs = [split_ecdsa_sig(s) for s in witness[:-1] if s[:1] == b"\x30"]
            assert sigs, "no signature found in time-lock witness"
        return dict(
            name=name,
            message=message,
            spk=spk,
            ver=version,
            lt=locktime,
            seq=sequence,
            check=("ecdsa", "SegwitV0", witness_script, keys, sigs),
        )

    if vtype == "p2pkh":
        sig, pubkey = parse_script_pushes(script_sig)
        return dict(
            name=name,
            message=message,
            spk=spk,
            ver=version,
            lt=locktime,
            seq=sequence,
            check=("ecdsa", "Legacy", spk, [pubkey], [split_ecdsa_sig(sig)]),
        )

    if vtype == "p2sh-multisig-2of2":
        pushes = parse_script_pushes(script_sig)
        assert pushes[0] == b""
        redeem = pushes[-1]
        assert (
            hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest()
            == spk[2:22]
        )
        keys = multisig_keys(redeem)
        sigs = [split_ecdsa_sig(s) for s in pushes[1:-1]]
        return dict(
            name=name,
            message=message,
            spk=spk,
            ver=version,
            lt=locktime,
            seq=sequence,
            check=("ecdsa", "Legacy", redeem, keys, sigs),
        )

    if vtype == "p2tr":
        assert (
            len(witness) == 1 and len(witness[0]) == 64
        ), "expected 64-byte keypath schnorr sig"
        return dict(
            name=name,
            message=message,
            spk=spk,
            ver=version,
            lt=locktime,
            seq=sequence,
            check=("schnorr_keypath", spk[2:34], witness[0]),
        )

    if vtype == "p2tr-time-lock":
        # script-path spend: [stack items..., leaf_script, control_block]. The first stack item
        # is the signature; further items (e.g. an empty IF-branch selector) only affect script
        # execution, not the sighash.
        assert len(witness) >= 3
        sig = witness[0]
        assert len(sig) == 64, "expected SIGHASH_DEFAULT schnorr sig"
        leaf_script = witness[-2]
        return dict(
            name=name,
            message=message,
            spk=spk,
            ver=version,
            lt=locktime,
            seq=sequence,
            check=(
                "schnorr_scriptpath",
                leaf_script,
                tapscript_xonly_keys(leaf_script),
                sig,
            ),
        )

    raise ValueError(f"unhandled vector type {vtype}")


# --- Rust emission -----------------------------------------------------------


def rust_bytes(b: bytes) -> str:
    return f'&hex!("{b.hex()}")' if b else "&[]"


def rust_bytes_list(items) -> str:
    return "&[" + ", ".join(rust_bytes(i) for i in items) + "]"


def emit(vectors, out):
    w = out.write
    w("""\
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

""")
    w("static SPEC_VECTORS: &[SpecVector] = &[\n")
    for v in vectors:
        c = v["check"]
        w("    SpecVector {\n")
        w(f'        name: "{v["name"]}",\n')
        w(f'        message: b"{v["message"].decode()}",\n')
        w(f'        script_pubkey: {rust_bytes(v["spk"])},\n')
        w(f'        version: {v["ver"]},\n')
        w(f'        locktime: {v["lt"]},\n')
        w(f'        sequence: {v["seq"]},\n')
        if c[0] == "ecdsa":
            _, mode, script_code, keys, sigs = c
            w("        check: Check::Ecdsa {\n")
            w(f"            mode: Mode::{mode},\n")
            w(f"            script_code: {rust_bytes(script_code)},\n")
            w(f"            pubkeys: {rust_bytes_list(keys)},\n")
            w(f"            sigs_der: {rust_bytes_list(sigs)},\n")
            w("        },\n")
        elif c[0] == "schnorr_keypath":
            _, key, sig = c
            w("        check: Check::SchnorrKeyPath {\n")
            w(f"            output_key: {rust_bytes(key)},\n")
            w(f"            sig: {rust_bytes(sig)},\n")
            w("        },\n")
        else:
            _, leaf_script, keys, sig = c
            w("        check: Check::SchnorrScriptPath {\n")
            w(f"            leaf_script: {rust_bytes(leaf_script)},\n")
            w(f"            xonly_key_candidates: {rust_bytes_list(keys)},\n")
            w(f"            sig: {rust_bytes(sig)},\n")
            w("        },\n")
        w("    },\n")
    w("];\n")
    w("""
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
""")


def main():
    vectors_path, out_path = sys.argv[1], sys.argv[2]
    data = json.load(open(vectors_path))
    converted = [convert(v, "simple") for v in data["simple"]]
    converted += [convert(v, "full") for v in data["full"]]
    with open(out_path, "w") as f:
        emit(converted, f)
    print(f"wrote {len(converted)} vectors to {out_path}")


if __name__ == "__main__":
    main()
