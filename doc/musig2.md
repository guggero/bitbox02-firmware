# MuSig2 transaction signing

The device acts as a BIP327 MuSig2 signer through the existing Bitcoin `signtx`
exchange. The host decodes the PSBT, supplies BIP373 records, verifies the returned
partial signatures, combines them, and finalizes the transaction. Firmware never
combines signatures. MuSig2 and ordinary Schnorr inputs do not use anti-klepto;
ordinary ECDSA inputs retain their existing anti-klepto exchange.

## Supported wallets

Register a BIP388 Taproot policy containing an aggregate key, for example:

- `tr(musig(@0,@1)/**)` for key-path signing.
- `tr(@0/<2;3>/*,pk(musig(@0,@1)/**))` for signing a tapscript leaf.

The existing policy UI displays the template and participant xpub origins.
Participants are sorted by their compressed origin public keys as in BIP390,
aggregated, and then derived using the BIP328 synthetic xpub and its standard
chain code. Branch/index derivations are plain tweaks. Key-path signing also
applies the TapTweak, including the policy's script tree root when present.

A MuSig input's `keypath` is an **address selector**: our participant's origin path
followed by the aggregate branch and address index. Only the origin is used to
derive the private signing key. For example, if `@0` has origin
`m/48'/1'/0'/3'`, selector `m/48'/1'/0'/3'/1/7` selects aggregate change address 7.
It does not mean that the participant private key is derived at `/1/7`.

The implementation supports Bitcoin mainnet and testnet wallet policies. It
supports one local participant contribution per transaction input, at most 16
MuSig inputs, at most 128 total inputs in a MuSig session, and the existing policy
limit of 20 keys. Ordinary simple-script and policy inputs can share a MuSig
transaction. Only SIGHASH_DEFAULT is supported for Taproot. Raw aggregate-key
wallets, custom aggregate chain codes, multiple contributions for one input,
legacy multisig configs mixed into this mode, BIP322, and silent-payment outputs
are not supported in MuSig mode.

## Wire exchange

1. Send `BTCSignInitRequest` with `musig2.phase = NONCE` and an empty session ID.
   The first `BTCSignNextResponse` acknowledges the mode with a fresh 32-byte
   `musig2_session_id`. Require this acknowledgement before streaming inputs;
   older firmware ignores unknown protobuf fields.
2. Stream the transaction as usual. Attach `BTCMuSig2Input` to each selected
   input in **both** input passes. The device validates policy ownership and
   reviews the transaction with the user before generating nonces.
3. Collect `musig2_result.public_nonce` contributions, including any result
   attached to `DONE`. No ordinary signatures are produced in this round.
   `DONE` repeats the session ID. Keep the same device/wallet/Noise session.
4. Exchange public nonces with the other participants through the PSBT. Resubmit
   the identical transaction with `musig2.phase = SIGN` and the returned session
   ID. Transaction fields, policies, input contexts, and output metadata must
   match the nonce round. The user reviews the transaction again.
5. For every `MUSIG2_NONCES` request, send `BTCRequest.musig2_nonces` containing
   the complete set of participants' public nonces, including the device's own.
   Records may arrive in any order. The firmware validates their tuple and
   reorders them to the aggregation order.
6. Collect `musig2_result.partial_signature`, also on `DONE`, and any ordinary
   input signatures. A partial signature is a 32-byte scalar, never an ordinary
   `has_signature`/`signature` result. Verify and combine on the host.

Each result carries its own input index. The response's `index` identifies the
**next request**, which may belong to a different input. After the nested nonce
request, its response is wrapped as `BTCResponse.sign_next`; direct input/output
requests still receive the direct `btc_sign_next` response, as in the existing
anti-klepto exchange.

## BIP373 mapping

The Python library accepts decoded records; it does not parse serialized PSBTs.
A coordinator retains its PSBT parser and maps fields as follows:

| PSBT input record | Firmware field |
| --- | --- |
| `0x1a` aggregate key (33 bytes) | `BTCMuSig2Input.aggregate_key` |
| `0x1a` value, concatenated compressed participant keys | `participant_pubkeys`, preserving order |
| Registered aggregate expression | `key_expression`, e.g. `musig(@0,@1)/**` |
| `0x1b` key data: participant key, context key, optional leaf hash | `BTCMuSig2Nonce.participant_pubkey`, enclosing `context_key`, `tapleaf_hash` |
| `0x1b` value (66 bytes) | `BTCMuSig2Nonce.public_nonce` |
| Public-nonce result | Insert `0x1b || participant_pubkey || context_key || [tapleaf_hash]`, value `public_nonce` |
| Partial-signature result | Insert `0x1c || participant_pubkey || context_key || [tapleaf_hash]`, value `partial_signature` |

The aggregate in `0x1a` must equal bare KeyAgg of the registered participant keys.
For nonce/signature record context keys, the firmware accepts the bare aggregate,
the BIP328-derived aggregate, or the final signing key **only after computing and
validating that alias**. This accommodates the distinction between the BIP373
prose and the final-key convention in btcd's `bip-musig2-psbt` fixtures. The exact
alias must remain unchanged throughout the session. Key-path records omit the
leaf hash. Script-path records carry the exact selected 32-byte leaf hash.
Unknown, missing, duplicated, mismatched, or malformed participant records fail.

## Python client

Create `BTCMuSig2Session({input_index: btc.BTCMuSig2Input(...)})` and pass it as
`musig2=session` to `device.btc_sign(...)`. The first call returns no ordinary
signatures and fills `session.results` with public nonces. Save those records
into the PSBT and collect all participants' nonces.

Call `session.begin_sign({input_index: btc.BTCMuSig2NoncesRequest(...)})`, then
call `device.btc_sign(...)` again with the same transaction arguments and session.
`session.results` now contains partial signatures. The usual return value contains
only ordinary input signatures. The client checks result routing and completeness.
`device.btc_musig2_abort(session.session_id)` abandons pending firmware state.

## Nonce lifecycle

There is one pending session per device. Secret nonces live only in zeroizing RAM
allocations and have no clone, serialization, or persistence interface. Nonce
randomness is fresh secret device randomness, distinct from the public session ID.
The nonce is bound to the participant, aggregate, sighash, and reviewed transaction.

A signing invocation takes ownership of the session before validation and user
review. Each secret nonce is removed before signing; signing errors, transaction
substitution, or user rejection destroy that round's remaining nonces. A completed
session cannot be retried. Explicit abort, wallet lock/unlock, USB cancellation,
a new Noise handshake, and power loss invalidate pending state. A dropped active
USB future destroys the secrets it owns. After failure, abandon PSBT public nonces
from that session and start a fresh round with all participants. Losing the final
nonce-round response may require reconnecting or aborting using the initial token.

## Verification

Tests cover BIP327 reference-derived primitive vectors, BIP328 derivation,
key-path and script-path signtx exchanges, multiple inputs, independent transaction
sighashes, malformed records, transaction substitution, single-use state,
capacity limits, cancellation, and Python transport compatibility.

To export public transcripts and check them with a local BIPs checkout:

```sh
# Run in the build container, from src/rust (choose an absolute output path).
BITBOX_MUSIG2_FIXTURES=/tmp/musig2-transcripts cargo test \
  -p bitbox02-rust --all-features test_musig2_signtx -- --test-threads 1

# Run where both the transcript directory and BIPs checkout are accessible.
python3 scripts/check_musig2_reference.py /tmp/musig2-transcripts \
  ../../bips/bip-0327/reference.py
```

The checker independently recomputes aggregate keys, verifies every partial,
combines on the host, and verifies the final BIP340 signatures. The protocol and
policy tests run with the normal single-threaded Rust workspace suite. Python
transport tests run with:

```sh
python3 -m unittest discover -s test/scripts -p test_musig2.py -v
```

Device timing, maximum-session heap/stack use, and physical unplug/reconnect
behavior still require hardware smoke testing; linker totals do not measure
peak runtime memory.
