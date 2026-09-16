#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Check exported signtx transcripts using the independent BIP327 Python reference.

Run the Rust test with BITBOX_MUSIG2_FIXTURES pointing to an output directory,
then pass that directory and the BIP327 reference.py path to this script.
Only public transcript data is exported. Signature combination stays on the host.
"""

import argparse
import importlib.util
import json
from pathlib import Path


def main() -> None:
    """Verify both participants and the final BIP340 signatures for each input."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transcripts", type=Path)
    parser.add_argument("reference", type=Path)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("bip327", args.reference)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {args.reference}")
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)

    for filename in ["keypath.json", "scriptpath.json"]:
        records = json.loads((args.transcripts / filename).read_text())
        assert records, "empty transcript"
        for record in records:
            pubkeys = list(map(bytes.fromhex, record["pubkeys"]))
            pubnonces = list(map(bytes.fromhex, record["pubnonces"]))
            tweaks = list(map(bytes.fromhex, record["tweaks"]))
            flags = record["is_xonly"]
            message = bytes.fromhex(record["message"])
            signatures = list(map(bytes.fromhex, record["partial_signatures"]))
            key = reference.key_agg_and_tweak(pubkeys, tweaks, flags)
            assert reference.cbytes(key.Q).hex() == record["aggregate_key"]
            for index, signature in enumerate(signatures):
                assert reference.partial_sig_verify(
                    signature, pubnonces, pubkeys, tweaks, flags, message, index
                ), f"{filename}: invalid partial signature {index}"
            session = reference.SessionContext(
                reference.nonce_agg(pubnonces), pubkeys, tweaks, flags, message
            )
            combined = reference.partial_sig_agg(signatures, session)
            assert reference.schnorr_verify(message, reference.get_xonly_pk(key), combined)
        print(f"{filename}: {len(records)} combined BIP340 signatures verified")


if __name__ == "__main__":
    main()
