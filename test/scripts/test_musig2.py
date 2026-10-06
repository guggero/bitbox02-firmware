# SPDX-License-Identifier: Apache-2.0

"""Exercise MuSig2 client streaming, including contributions on DONE."""

import sys
import unittest
from pathlib import Path

import semver

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "py" / "bitbox02"))
from bitbox02.bitbox02 import (  # noqa: E402
    BitBox02,
    BTCMuSig2Session,
    BTCOutputExternal,
    btc,
    hww,
    btc_sign_needs_prevtxs,
)


TOKEN = b"s" * 32
KEY = b"\x02" + b"k" * 32
CONTEXT = btc.BTCMuSig2Input(
    key_expression="musig(@0,@1)/**",
    aggregate_key=KEY,
    participant_pubkeys=[KEY],
    context_key=KEY,
)
CONFIG = btc.BTCScriptConfigWithKeypath(
    script_config=btc.BTCScriptConfig(
        policy=btc.BTCScriptConfig.Policy(policy="tr(musig(@0,@1)/**)")
    ),
)
INPUT = dict(
    prev_out_hash=b"h" * 32,
    prev_out_index=0,
    prev_out_value=10000,
    sequence=0xFFFFFFFF,
    keypath=[0, 0],
    script_config_index=0,
    prev_tx=None,
)
OUTPUT = BTCOutputExternal(btc.P2WPKH, b"o" * 20, 19000)


class Device:
    """Script the transport without bypassing the public signing driver."""

    btc_sign = BitBox02.btc_sign
    version = semver.VersionInfo(9, 30, 0)
    debug = False

    def __init__(self, exchanges):
        self.exchanges = iter(exchanges)
        self.requests = []

    def _require_atleast(self, version):
        assert self.version >= version

    def exchange(self, request, name):
        expected, response = next(self.exchanges)
        assert name == expected, (name, expected)
        self.requests.append(request)
        return response

    def _msg_query(self, request, expected_response):
        assert expected_response == "btc_sign_next"
        return hww.Response(btc_sign_next=self.exchange(request, request.WhichOneof("request")))

    def _btc_msg_query(self, request, expected_response):
        assert expected_response == "sign_next"
        return btc.BTCResponse(sign_next=self.exchange(request, request.WhichOneof("request")))


def response(kind, index=0, result=None, token=b"", musig2_index=0):
    return btc.BTCSignNextResponse(
        type=kind,
        index=index,
        musig2_results=[] if result is None else [result],
        musig2_session_id=token,
        musig2_index=musig2_index,
    )


def contribution(index, signing, nonce=None):
    result = btc.BTCMuSig2Result(input_index=index, participant_pubkey=KEY, context_key=KEY)
    if nonce is None:
        nonce = not signing
    if signing:
        result.partial_signature = b"p" * 32
    if nonce:
        result.public_nonce = b"n" * 66
    return result


def peer_nonces():
    return {
        index: btc.BTCMuSig2NoncesRequest(
            input_index=index,
            context_key=KEY,
            nonces=[
                btc.BTCMuSig2Nonce(participant_pubkey=b"\x03" + b"p" * 32, public_nonce=b"m" * 66)
            ],
        )
        for index in range(2)
    }


def exchanges(signing, nonce=None):
    next_type = btc.BTCSignNextResponse
    result = [
        ("btc_sign_init", response(next_type.INPUT, token=TOKEN)),
        ("btc_sign_input", response(next_type.INPUT, 1)),
        ("btc_sign_input", response(next_type.OUTPUT)),
        ("btc_sign_output", response(next_type.INPUT)),
    ]
    for index in range(2):
        request_name = "btc_sign_input"
        if signing:
            result.append((request_name, response(next_type.MUSIG2_NONCES, index)))
            request_name = "musig2_nonces"
        result.append(
            (
                request_name,
                response(
                    next_type.DONE if index == 1 else next_type.INPUT,
                    1,
                    contribution(index, signing, nonce),
                    TOKEN if index == 1 else b"",
                ),
            )
        )
    return result


class MuSig2Tests(unittest.TestCase):
    def test_two_rounds(self):
        self.assertFalse(btc_sign_needs_prevtxs([CONFIG]))
        session = BTCMuSig2Session({0: CONTEXT, 1: CONTEXT})
        for signing in [False, True]:
            device = Device(exchanges(signing))
            self.assertEqual(
                device.btc_sign(btc.TBTC, [CONFIG], [INPUT, INPUT], [OUTPUT], musig2=session), []
            )
            self.assertEqual(session.session_id, TOKEN)
            self.assertEqual(set(session.results), {(0, 0), (1, 0)})
            for request in device.requests:
                if isinstance(request, hww.Request) and request.HasField("btc_sign_input"):
                    self.assertEqual(list(request.btc_sign_input.musig2), [CONTEXT])
                    self.assertFalse(request.btc_sign_input.HasField("host_nonce_commitment"))
            self.assertIsNone(next(device.exchanges, None))
            if not signing:
                session.begin_sign(
                    {
                        index: btc.BTCMuSig2NoncesRequest(
                            input_index=index,
                            context_key=KEY,
                            nonces=[
                                btc.BTCMuSig2Nonce(participant_pubkey=KEY, public_nonce=b"n" * 66)
                            ],
                        )
                        for index in range(2)
                    }
                )

    def test_nonce_and_sign(self):
        session = BTCMuSig2Session({0: CONTEXT, 1: CONTEXT})
        session.begin_nonce_and_sign(peer_nonces())
        device = Device(exchanges(True, True))
        self.assertEqual(
            device.btc_sign(btc.TBTC, [CONFIG], [INPUT, INPUT], [OUTPUT], musig2=session), []
        )
        init = device.requests[0].btc_sign_init.musig2
        self.assertEqual(init.phase, btc.BTCMuSig2Init.NONCE_AND_SIGN)
        self.assertEqual(init.session_id, b"")
        self.assertEqual(session.session_id, TOKEN)
        for index in range(2):
            self.assertEqual(session.results[(index, 0)].public_nonce, b"n" * 66)
            self.assertEqual(session.results[(index, 0)].partial_signature, b"p" * 32)
        nonce_requests = [
            request.musig2_nonces
            for request in device.requests
            if isinstance(request, btc.BTCRequest)
        ]
        self.assertEqual(nonce_requests, [peer_nonces()[0], peer_nonces()[1]])
        self.assertIsNone(next(device.exchanges, None))

        # A single-round session cannot be combined with the two-round API.
        with self.assertRaises(ValueError):
            session.begin_sign(peer_nonces())
        started = BTCMuSig2Session({0: CONTEXT})
        started.session_id = TOKEN
        with self.assertRaises(ValueError):
            started.begin_nonce_and_sign({0: peer_nonces()[0]})

        # Both contributions are required in this phase.
        session = BTCMuSig2Session({0: CONTEXT})
        session.begin_nonce_and_sign({0: peer_nonces()[0]})
        with self.assertRaises(ValueError):
            session.collect(contribution(0, True, False))
        with self.assertRaises(ValueError):
            session.collect(contribution(0, False))
        session.collect(contribution(0, True, True))

    def test_older_firmware(self):
        device = Device([("btc_sign_init", response(btc.BTCSignNextResponse.INPUT))])
        with self.assertRaisesRegex(ValueError, "acknowledge"):
            device.btc_sign(
                btc.TBTC, [CONFIG], [INPUT], [OUTPUT], musig2=BTCMuSig2Session({0: CONTEXT})
            )
        self.assertEqual(len(device.requests), 1)

    def test_missing_done_result(self):
        script = exchanges(False)
        script[-1][1].ClearField("musig2_results")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            Device(script).btc_sign(
                btc.TBTC,
                [CONFIG],
                [INPUT, INPUT],
                [OUTPUT],
                musig2=BTCMuSig2Session({0: CONTEXT, 1: CONTEXT}),
            )

    def test_result_routing(self):
        session = BTCMuSig2Session({0: CONTEXT})
        wrong = contribution(0, False)
        wrong.context_key = b"x" * 33
        with self.assertRaises(ValueError):
            session.collect(wrong)
        with self.assertRaises(ValueError):
            session.collect(contribution(0, True))
        session.collect(contribution(0, False))
        with self.assertRaises(ValueError):
            session.collect(contribution(0, False))

    def test_ordinary_signatures(self):
        script = exchanges(False)
        script[0][1].ClearField("musig2_session_id")
        for _, reply in script:
            if reply.musig2_results:
                reply.ClearField("musig2_results")
                reply.has_signature = True
                reply.signature = b"s" * 64
        self.assertEqual(
            Device(script).btc_sign(btc.TBTC, [CONFIG], [INPUT, INPUT], [OUTPUT]),
            [(0, b"s" * 64), (1, b"s" * 64)],
        )

    def test_several_contexts(self):
        # The input's second context is a leaf the host cannot complete: it is
        # skipped in the signing round and gets no result.
        leaf = btc.BTCMuSig2Input()
        leaf.CopyFrom(CONTEXT)
        leaf.key_expression = "musig(@0,@2)/**"
        leaf.tapleaf_hash = b"l" * 32
        session = BTCMuSig2Session({0: [CONTEXT, leaf]})
        next_type = btc.BTCSignNextResponse
        nonce_round = [
            ("btc_sign_init", response(next_type.INPUT, token=TOKEN)),
            ("btc_sign_input", response(next_type.OUTPUT)),
            ("btc_sign_output", response(next_type.INPUT)),
        ]
        leaf_nonce = contribution(0, False)
        leaf_nonce.tapleaf_hash = leaf.tapleaf_hash
        done = response(next_type.DONE, 0, contribution(0, False), TOKEN)
        done.musig2_results.append(leaf_nonce)
        nonce_round.append(("btc_sign_input", done))
        device = Device(nonce_round)
        device.btc_sign(btc.TBTC, [CONFIG], [INPUT], [OUTPUT], musig2=session)
        self.assertEqual(set(session.results), {(0, 0), (0, 1)})
        sent = [
            list(request.btc_sign_input.musig2)
            for request in device.requests
            if isinstance(request, hww.Request) and request.HasField("btc_sign_input")
        ]
        self.assertEqual(sent, [[CONTEXT, leaf], [CONTEXT, leaf]])

        complete = btc.BTCMuSig2NoncesRequest(
            input_index=0,
            context_key=KEY,
            nonces=[btc.BTCMuSig2Nonce(participant_pubkey=KEY, public_nonce=b"n" * 66)],
        )
        skipped = btc.BTCMuSig2NoncesRequest(
            input_index=0, context_key=KEY, tapleaf_hash=leaf.tapleaf_hash, skip=True
        )
        session.begin_sign({0: complete, (0, 1): skipped})
        signing_round = nonce_round[:3] + [
            ("btc_sign_input", response(next_type.MUSIG2_NONCES, 0)),
            ("musig2_nonces", response(next_type.MUSIG2_NONCES, 0, musig2_index=1)),
            ("musig2_nonces", response(next_type.DONE, 0, contribution(0, True), TOKEN)),
        ]
        device = Device(signing_round)
        device.btc_sign(btc.TBTC, [CONFIG], [INPUT], [OUTPUT], musig2=session)
        self.assertEqual(set(session.results), {(0, 0)})
        nonce_requests = [
            request.musig2_nonces
            for request in device.requests
            if isinstance(request, btc.BTCRequest)
        ]
        self.assertEqual(nonce_requests, [complete, skipped])

        # A result for the skipped context is refused.
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            session.collect(leaf_nonce)


if __name__ == "__main__":
    unittest.main()
