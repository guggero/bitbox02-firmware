// SPDX-License-Identifier: Apache-2.0

//! Volatile, single-use BIP373 signing sessions. Only public data crosses USB.

use alloc::vec::Vec;
use bitbox_secp256k1::musig::SecretNonce;
use core::cell::RefCell;
use prost::Message;
use sha2::{Digest, Sha256};

use super::{Error, pb, policies::musig::SigningContext, script_configs::ValidatedScriptConfig};
use pb::btc_mu_sig2_init::Phase;

/// Bound both retained nonces and transient per-input replay commitments.
pub const MAX_NONCES: usize = 16;
pub const MAX_INPUTS: usize = 128;

/// A retained secret nonce, for the context at `position` of the input at
/// `index`.
struct Slot {
    index: u32,
    position: u32,
    nonce: SecretNonce,
}

struct Pending {
    id: [u8; 32],
    transaction: [u8; 32],
    slots: Vec<Slot>,
}

struct PendingCell(RefCell<Option<Pending>>);
// SAFETY: API workflows run on one thread, including the single-threaded test
// runner. No borrow is held across an await or a call into another subsystem.
unsafe impl Sync for PendingCell {}
static PENDING: PendingCell = PendingCell(RefCell::new(None));

/// Invalidate pending nonces on wallet/transport changes. Dropping each secret
/// nonce zeroizes its allocation; no counter or secret is persisted in flash.
pub fn clear() {
    PENDING.0.borrow_mut().take();
}

/// Explicitly abandon the identified round. A stale identifier is an error.
pub fn abort(id: &[u8]) -> Result<(), Error> {
    let pending = PENDING.0.borrow_mut().take().ok_or(Error::InvalidState)?;
    if id != pending.id {
        return Err(Error::InvalidState);
    }
    Ok(())
}

/// What a round contributes to each MuSig input.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Generate and retain a secret nonce, return the public nonce.
    Nonce,
    /// Consume a retained secret nonce, return a partial signature.
    Sign,
    /// Last participant to contribute a nonce: generate a nonce once all other
    /// participants' nonces are known and sign with it right away. Nothing is
    /// retained, so the round neither needs nor touches pending storage.
    NonceAndSign,
}

/// An active invocation owns all its secrets. Dropping its future on cancellation
/// erases them. Only a successful nonce round returns them to pending storage.
pub struct Round {
    pending: Pending,
    pub mode: Mode,
    hasher: Sha256,
    inputs: Vec<[u8; 32]>,
    /// The number of MuSig contexts of all inputs.
    num_nonces: usize,
    /// The number of contexts NONCE_AND_SIGN contributed to or skipped.
    num_handled: usize,
    approved: bool,
}

fn hash_message(hasher: &mut Sha256, message: &impl Message) {
    let bytes = message.encode_to_vec();
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn input_commitment(input: &pb::BtcSignInputRequest) -> [u8; 32] {
    let mut input = input.clone();
    // The ordinary ECDSA exchange is independent of transaction authorization
    // and can have fresh host entropy in round two. MuSig inputs reject it.
    input.host_nonce_commitment = None;
    let mut hash = Sha256::new();
    hash.update(b"BitBox/MuSig2/input/v1");
    hash_message(&mut hash, &input);
    hash.finalize().into()
}

impl Round {
    /// Public correlation token, also acknowledges support before inputs arrive.
    pub fn session_id(&self) -> &[u8; 32] {
        &self.pending.id
    }

    /// Reserve a new round or take the existing session before processing any
    /// host data. A signing error therefore cannot leave reusable nonce state.
    pub async fn begin(
        hal: &mut impl crate::hal::Hal,
        request: &pb::BtcSignInitRequest,
    ) -> Result<Option<Self>, Error> {
        let Some(init) = &request.musig2 else {
            return Ok(None);
        };
        let mode = match Phase::try_from(init.phase)? {
            Phase::Nonce if init.session_id.is_empty() => Mode::Nonce,
            Phase::Sign if init.session_id.len() == 32 => Mode::Sign,
            Phase::NonceAndSign if init.session_id.is_empty() => Mode::NonceAndSign,
            _ => return Err(Error::InvalidInput),
        };
        if mode == Mode::Nonce && PENDING.0.borrow().is_some() {
            return Err(Error::InvalidState);
        }
        let pending = if mode == Mode::Sign {
            let pending = PENDING.0.borrow_mut().take().ok_or(Error::InvalidState)?;
            if init.session_id != pending.id {
                return Err(Error::InvalidState);
            }
            pending
        } else {
            Pending {
                id: **bitbox_core_utils::random::random_32_bytes_from_hal(hal)
                    .await
                    .map_err(|_| Error::Generic)?,
                transaction: [0; 32],
                slots: Vec::new(),
            }
        };
        if request.num_inputs == 0
            || request.num_inputs as usize > MAX_INPUTS
            || request.bip322_message.is_some()
            || request.contains_silent_payment_outputs
        {
            return Err(Error::InvalidInput);
        }
        let mut normalized = request.clone();
        normalized.musig2 = None;
        let mut hasher = Sha256::new();
        hasher.update(b"BitBox/MuSig2/transaction/v1");
        hash_message(&mut hasher, &normalized);
        Ok(Some(Self {
            pending,
            mode,
            hasher,
            inputs: Vec::new(),
            num_nonces: 0,
            num_handled: 0,
            approved: false,
        }))
    }

    /// Commit each complete input, including its policy context, in pass one.
    pub fn input(&mut self, input: &pb::BtcSignInputRequest) -> Result<(), Error> {
        if self.inputs.len() >= MAX_INPUTS {
            return Err(Error::InvalidInput);
        }
        // Each context is a different aggregate or leaf of the input.
        for (position, metadata) in input.musig2.iter().enumerate() {
            if input.musig2[..position].iter().any(|other| {
                other.key_expression == metadata.key_expression
                    && other.tapleaf_hash == metadata.tapleaf_hash
            }) {
                return Err(Error::InvalidInput);
            }
        }
        self.num_nonces += input.musig2.len();
        if self.num_nonces > MAX_NONCES {
            return Err(Error::InvalidInput);
        }
        let hash = input_commitment(input);
        self.inputs.push(hash);
        self.hasher.update(hash);
        Ok(())
    }

    /// Bind output values, recipient scripts and change metadata to this round.
    pub fn output(&mut self, output: &pb::BtcSignOutputRequest) {
        hash_message(&mut self.hasher, output);
    }

    /// After transaction review, bind new nonces or verify the original approval.
    pub fn approve(&mut self) -> Result<(), Error> {
        if self.num_nonces == 0 {
            return Err(Error::InvalidInput);
        }
        let transaction: [u8; 32] = self.hasher.clone().finalize().into();
        if self.mode != Mode::Sign {
            self.pending.transaction = transaction;
        } else if self.pending.transaction != transaction
            || self.pending.slots.len() != self.num_nonces
        {
            return Err(Error::InvalidInput);
        }
        self.approved = true;
        Ok(())
    }

    /// Reject host substitutions between transaction streaming passes.
    pub fn check_input(&self, index: u32, input: &pb::BtcSignInputRequest) -> Result<(), Error> {
        if !self.approved || self.inputs.get(index as usize) != Some(&input_commitment(input)) {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }

    /// Derive fresh secret nonce material with independent secret randomness.
    pub async fn nonce(
        &mut self,
        hal: &mut impl crate::hal::Hal,
        index: u32,
        position: u32,
        context: &SigningContext,
        message: &[u8; 32],
    ) -> Result<[u8; 66], Error> {
        if !self.approved
            || self.mode != Mode::Nonce
            || self.pending.slots.len() >= MAX_NONCES
            || self
                .pending
                .slots
                .iter()
                .any(|slot| slot.index == index && slot.position == position)
        {
            return Err(Error::InvalidState);
        }
        let nonce = self.generate_nonce(hal, context, message).await?;
        let public = nonce.public_nonce();
        self.pending.slots.push(Slot {
            index,
            position,
            nonce,
        });
        Ok(public)
    }

    /// Generate a secret nonce from fresh device randomness, bound to our key,
    /// the aggregate, the message and the reviewed transaction.
    async fn generate_nonce(
        &self,
        hal: &mut impl crate::hal::Hal,
        context: &SigningContext,
        message: &[u8; 32],
    ) -> Result<SecretNonce, Error> {
        let secret = crate::keystore::secp256k1_get_private_key(hal, &context.keypath).await?;
        let random = bitbox_core_utils::random::random_32_bytes_from_hal(hal)
            .await
            .map_err(|_| Error::Generic)?;
        Ok(SecretNonce::generate(
            &random,
            secret.as_slice().try_into().map_err(|_| Error::Generic)?,
            &context.aggregate,
            message,
            &self.pending.transaction,
        )?)
    }

    /// Contribute as the last participant: every other participant's public
    /// nonce is already fixed in `request`, so a fresh nonce can be generated and
    /// consumed immediately. The secret nonce never outlives this call.
    pub async fn nonce_and_sign(
        &mut self,
        hal: &mut impl crate::hal::Hal,
        index: u32,
        metadata: &pb::BtcMuSig2Input,
        context: &SigningContext,
        message: &[u8; 32],
        request: &pb::BtcMuSig2NoncesRequest,
    ) -> Result<([u8; 66], [u8; 32]), Error> {
        if !self.approved || self.mode != Mode::NonceAndSign || self.num_handled >= self.num_nonces
        {
            return Err(Error::InvalidState);
        }
        // Count the attempt before anything can fail, so a context cannot be
        // retried within the same round.
        self.num_handled += 1;
        let nonce = self.generate_nonce(hal, context, message).await?;
        let public = nonce.public_nonce();
        let nonces = order_nonces(index, metadata, context, request, Some(&public))?;
        let secret = crate::keystore::secp256k1_get_private_key(hal, &context.keypath).await?;
        let signature = nonce
            .sign(
                secret.as_slice().try_into().map_err(|_| Error::Generic)?,
                &context.aggregate,
                &nonces,
                message,
            )
            .map_err(|_| Error::InvalidInput)?;
        Ok((public, signature))
    }

    /// Remove a nonce before signing or accessing the keystore. Every error
    /// consumes it, and dropping this round also destroys remaining slots.
    pub async fn sign(
        &mut self,
        hal: &mut impl crate::hal::Hal,
        index: u32,
        position: u32,
        context: &SigningContext,
        message: &[u8; 32],
        nonces: &[[u8; 66]],
    ) -> Result<[u8; 32], Error> {
        if self.mode != Mode::Sign {
            return Err(Error::InvalidState);
        }
        let slot = self.take_slot(index, position)?;
        let secret = crate::keystore::secp256k1_get_private_key(hal, &context.keypath).await?;
        slot.nonce
            .sign(
                secret.as_slice().try_into().map_err(|_| Error::Generic)?,
                &context.aggregate,
                nonces,
                message,
            )
            .map_err(|_| Error::InvalidInput)
    }

    /// Remove the retained nonce of a context.
    fn take_slot(&mut self, index: u32, position: u32) -> Result<Slot, Error> {
        if !self.approved {
            return Err(Error::InvalidState);
        }
        let slot = self
            .pending
            .slots
            .iter()
            .position(|slot| slot.index == index && slot.position == position)
            .ok_or(Error::InvalidState)?;
        Ok(self.pending.slots.remove(slot))
    }

    /// Contribute nothing to a context the host cannot complete, e.g. because
    /// a spend path's other participant is not taking part. A retained nonce
    /// is destroyed, never reused.
    pub fn skip(&mut self, index: u32, position: u32) -> Result<(), Error> {
        match self.mode {
            Mode::Sign => {
                self.take_slot(index, position)?;
            }
            Mode::NonceAndSign => {
                if !self.approved || self.num_handled >= self.num_nonces {
                    return Err(Error::InvalidState);
                }
                self.num_handled += 1;
            }
            Mode::Nonce => return Err(Error::InvalidState),
        }
        Ok(())
    }

    /// Complete a round. Return only its public handle; signing rounds retain
    /// no state, so repeating a completed operation cannot reuse a nonce.
    pub fn finish(self) -> Result<[u8; 32], Error> {
        let id = self.pending.id;
        if !self.approved {
            return Err(Error::InvalidState);
        }
        match self.mode {
            Mode::Nonce => {
                if self.pending.slots.len() != self.num_nonces {
                    return Err(Error::InvalidState);
                }
                *PENDING.0.borrow_mut() = Some(self.pending);
            }
            Mode::Sign => {
                if !self.pending.slots.is_empty() {
                    return Err(Error::InvalidState);
                }
            }
            Mode::NonceAndSign => {
                if self.num_handled != self.num_nonces {
                    return Err(Error::InvalidState);
                }
            }
        }
        Ok(id)
    }
}

/// Resolve BIP373 metadata only through a registered policy. The three valid
/// aggregate-key aliases are checked against actual derivation, never trusted.
pub fn context(
    config: &ValidatedScriptConfig,
    input: &pb::BtcSignInputRequest,
    metadata: &pb::BtcMuSig2Input,
) -> Result<SigningContext, Error> {
    if input.host_nonce_commitment.is_some() {
        return Err(Error::InvalidInput);
    }
    let ValidatedScriptConfig::Policy { parsed_policy, .. } = config else {
        return Err(Error::InvalidInput);
    };
    let context = parsed_policy.musig_context(&metadata.key_expression, &input.keypath)?;
    if metadata.aggregate_key != context.bare_key
        || metadata.participant_pubkeys.len() != context.participants.len()
        || !metadata
            .participant_pubkeys
            .iter()
            .zip(&context.participants)
            .all(|(a, b)| a.as_slice() == b)
        || metadata.tapleaf_hash.as_deref()
            != context.tapleaf_hash.as_ref().map(|hash| hash.as_slice())
    {
        return Err(Error::InvalidInput);
    }
    let final_key = context.aggregate.public_key().serialize();
    if ![context.bare_key, context.internal_key, final_key]
        .iter()
        .any(|key| metadata.context_key == key)
    {
        return Err(Error::InvalidInput);
    }
    Ok(context)
}

/// Match the complete BIP373 context and order public nonces by participant.
///
/// Without `ours`, the request must contain every participant's nonce, including
/// ours. With `ours`, the device's freshly generated nonce, the request must
/// contain every other participant's nonce and must not contain ours.
pub fn order_nonces(
    index: u32,
    metadata: &pb::BtcMuSig2Input,
    context: &SigningContext,
    request: &pb::BtcMuSig2NoncesRequest,
    ours: Option<&[u8; 66]>,
) -> Result<Vec<[u8; 66]>, Error> {
    let expected = context.participants.len() - usize::from(ours.is_some());
    if request.input_index != index
        || request.context_key != metadata.context_key
        || request.tapleaf_hash != metadata.tapleaf_hash
        || request.nonces.len() != expected
    {
        return Err(Error::InvalidInput);
    }
    context
        .participants
        .iter()
        .map(|key| {
            if let (Some(ours), true) = (ours, key == &context.participant) {
                if request
                    .nonces
                    .iter()
                    .any(|nonce| nonce.participant_pubkey.as_slice() == key)
                {
                    return Err(Error::InvalidInput);
                }
                return Ok(*ours);
            }
            let mut matches = request
                .nonces
                .iter()
                .filter(|nonce| nonce.participant_pubkey.as_slice() == key);
            let nonce = matches.next().ok_or(Error::InvalidInput)?;
            if matches.next().is_some() {
                return Err(Error::InvalidInput);
            }
            nonce
                .public_nonce
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidInput)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hal::testing::TestingHal;
    use bitbox_secp256k1::{SECP256K1, musig::KeyAgg};
    use bitcoin::secp256k1::{PublicKey, SecretKey};

    async fn fixture(
        hal: &mut TestingHal<'_>,
    ) -> (
        SigningContext,
        pb::BtcSignInitRequest,
        pb::BtcSignInputRequest,
    ) {
        crate::keystore::testing::mock_unlocked();
        clear();
        let keypath = vec![0x80000000];
        let secret = crate::keystore::secp256k1_get_private_key(hal, &keypath)
            .await
            .unwrap();
        let participant =
            PublicKey::from_secret_key(SECP256K1, &SecretKey::from_slice(&secret).unwrap())
                .serialize();
        let other =
            PublicKey::from_secret_key(SECP256K1, &SecretKey::from_slice(&[2; 32]).unwrap())
                .serialize();
        let participants = vec![participant, other];
        let aggregate = KeyAgg::new(&participants).unwrap();
        let bare_key = aggregate.public_key().serialize();
        let context = SigningContext {
            aggregate,
            participants,
            participant,
            keypath,
            bare_key,
            internal_key: bare_key,
            tapleaf_hash: None,
        };
        let request = pb::BtcSignInitRequest {
            num_inputs: 1,
            num_outputs: 1,
            musig2: Some(pb::BtcMuSig2Init {
                phase: Phase::Nonce as _,
                session_id: vec![],
            }),
            ..Default::default()
        };
        let input = pb::BtcSignInputRequest {
            musig2: vec![Default::default()],
            ..Default::default()
        };
        (context, request, input)
    }

    async fn pending(
        hal: &mut TestingHal<'_>,
        context: &SigningContext,
        request: &pb::BtcSignInitRequest,
        input: &pb::BtcSignInputRequest,
    ) -> ([u8; 32], [u8; 66]) {
        let mut round = Round::begin(hal, request).await.unwrap().unwrap();
        round.input(input).unwrap();
        round.output(&Default::default());
        round.approve().unwrap();
        let public = round.nonce(hal, 0, 0, context, &[42; 32]).await.unwrap();
        (round.finish().unwrap(), public)
    }

    #[async_test::test]
    async fn test_round_sign_once() {
        let mut hal = TestingHal::new();
        let (context, mut request, input) = fixture(&mut hal).await;
        let (id, public) = pending(&mut hal, &context, &request, &input).await;
        assert!(Round::begin(&mut hal, &request).await.is_err());
        request.musig2 = Some(pb::BtcMuSig2Init {
            phase: Phase::Sign as _,
            session_id: id.to_vec(),
        });
        let mut round = Round::begin(&mut hal, &request).await.unwrap().unwrap();
        round.input(&input).unwrap();
        round.output(&Default::default());
        round.approve().unwrap();
        round.check_input(0, &input).unwrap();
        let other =
            SecretNonce::generate(&[3; 32], &[2; 32], &context.aggregate, &[42; 32], &[4; 32])
                .unwrap();
        let nonces = [public, other.public_nonce()];
        round
            .sign(&mut hal, 0, 0, &context, &[42; 32], &nonces)
            .await
            .unwrap();
        assert!(
            round
                .sign(&mut hal, 0, 0, &context, &[42; 32], &nonces)
                .await
                .is_err()
        );
        round.finish().unwrap();
        assert!(Round::begin(&mut hal, &request).await.is_err());
    }

    #[async_test::test]
    async fn test_round_nonce_and_sign_once() {
        let mut hal = TestingHal::new();
        let (context, mut request, input) = fixture(&mut hal).await;
        request.musig2 = Some(pb::BtcMuSig2Init {
            phase: Phase::NonceAndSign as _,
            session_id: vec![],
        });
        let metadata = pb::BtcMuSig2Input::default();
        let other =
            SecretNonce::generate(&[3; 32], &[2; 32], &context.aggregate, &[42; 32], &[4; 32])
                .unwrap();
        let nonces_request = pb::BtcMuSig2NoncesRequest {
            nonces: vec![pb::BtcMuSig2Nonce {
                participant_pubkey: context.participants[1].to_vec(),
                public_nonce: other.public_nonce().to_vec(),
            }],
            ..Default::default()
        };

        let mut round = Round::begin(&mut hal, &request).await.unwrap().unwrap();
        round.input(&input).unwrap();
        round.output(&Default::default());
        // Nothing may be contributed before the transaction is approved.
        assert!(
            round
                .nonce_and_sign(&mut hal, 0, &metadata, &context, &[42; 32], &nonces_request)
                .await
                .is_err()
        );
        round.approve().unwrap();
        // The two-round operations are not available in this mode.
        assert!(
            round
                .nonce(&mut hal, 0, 0, &context, &[42; 32])
                .await
                .is_err()
        );
        assert!(
            round
                .sign(&mut hal, 0, 0, &context, &[42; 32], &[[0; 66]; 2])
                .await
                .is_err()
        );
        let (public, signature) = round
            .nonce_and_sign(&mut hal, 0, &metadata, &context, &[42; 32], &nonces_request)
            .await
            .unwrap();
        bitbox_secp256k1::musig::verify_partial(
            &context.aggregate,
            &[public, other.public_nonce()],
            &[42; 32],
            0,
            &signature,
        )
        .unwrap();
        // Each input contributes once per round.
        assert!(
            round
                .nonce_and_sign(&mut hal, 0, &metadata, &context, &[42; 32], &nonces_request)
                .await
                .is_err()
        );
        round.finish().unwrap();
        assert!(PENDING.0.borrow().is_none());

        // A round that did not contribute to every MuSig input cannot finish.
        let mut round = Round::begin(&mut hal, &request).await.unwrap().unwrap();
        round.input(&input).unwrap();
        round.output(&Default::default());
        round.approve().unwrap();
        assert!(round.finish().is_err());

        // A pending nonce round is neither required nor consumed.
        request.musig2.as_mut().unwrap().phase = Phase::Nonce as _;
        let (id, _) = pending(&mut hal, &context, &request, &input).await;
        request.musig2.as_mut().unwrap().phase = Phase::NonceAndSign as _;
        assert!(Round::begin(&mut hal, &request).await.unwrap().is_some());
        assert_eq!(PENDING.0.borrow().as_ref().unwrap().id, id);
        request.musig2.as_mut().unwrap().session_id = id.to_vec();
        assert!(Round::begin(&mut hal, &request).await.is_err());
        clear();
    }

    #[async_test::test]
    async fn test_round_rejects_substitution_and_cleans_up() {
        let mut hal = TestingHal::new();
        let (context, request, input) = fixture(&mut hal).await;
        for mutation in 0..6 {
            let (id, _) = pending(&mut hal, &context, &request, &input).await;
            let mut signing = request.clone();
            signing.musig2 = Some(pb::BtcMuSig2Init {
                phase: Phase::Sign as _,
                session_id: id.to_vec(),
            });
            if mutation == 0 {
                signing.locktime = 1;
            }
            let mut round = Round::begin(&mut hal, &signing).await.unwrap().unwrap();
            let mut changed = input.clone();
            if mutation == 1 {
                changed.prev_out_value = 1;
            }
            if mutation == 2 {
                changed.musig2[0].context_key = vec![2; 33];
            }
            round.input(&changed).unwrap();
            let mut output = pb::BtcSignOutputRequest::default();
            if mutation == 3 {
                output.value = 1;
            }
            round.output(&output);
            if mutation < 4 {
                assert!(round.approve().is_err());
            } else {
                round.approve().unwrap();
                if mutation == 4 {
                    changed.keypath.push(1);
                    assert!(round.check_input(0, &changed).is_err());
                } else {
                    assert!(
                        round
                            .sign(&mut hal, 0, 0, &context, &[42; 32], &[[0; 66]; 2])
                            .await
                            .is_err()
                    );
                    assert!(round.pending.slots.is_empty());
                }
            }
            drop(round);
            assert!(Round::begin(&mut hal, &signing).await.is_err());
        }
        for cleanup in 0..3 {
            let (id, _) = pending(&mut hal, &context, &request, &input).await;
            match cleanup {
                0 => crate::async_usb::cancel(),
                1 => crate::keystore::lock(),
                _ => abort(&id).unwrap(),
            }
            assert!(PENDING.0.borrow().is_none());
            crate::keystore::testing::mock_unlocked();
        }
    }

    #[async_test::test]
    async fn test_round_limits_and_approval() {
        let mut hal = TestingHal::new();
        let (context, mut request, input) = fixture(&mut hal).await;
        request.num_inputs = MAX_INPUTS as u32 + 1;
        assert!(Round::begin(&mut hal, &request).await.is_err());
        request.num_inputs = MAX_INPUTS as u32;
        let mut round = Round::begin(&mut hal, &request).await.unwrap().unwrap();
        assert!(
            round
                .nonce(&mut hal, 0, 0, &context, &[42; 32])
                .await
                .is_err()
        );
        assert!(round.approve().is_err());
        for _ in 0..MAX_NONCES {
            round.input(&input).unwrap();
        }
        assert!(round.input(&input).is_err());
        drop(round);
        // A dropped nonce round leaves no pending storage, even before approval.
        assert!(PENDING.0.borrow().is_none());
        request.contains_silent_payment_outputs = true;
        assert!(Round::begin(&mut hal, &request).await.is_err());
        request.contains_silent_payment_outputs = false;
        request.bip322_message = Some(vec![]);
        assert!(Round::begin(&mut hal, &request).await.is_err());
    }

    #[async_test::test]
    async fn test_order_nonces_rejects_wrong_contexts() {
        let mut hal = TestingHal::new();
        let (context, _, _) = fixture(&mut hal).await;
        let metadata = pb::BtcMuSig2Input {
            context_key: context.bare_key.to_vec(),
            tapleaf_hash: Some(vec![3; 32]),
            ..Default::default()
        };
        let request = pb::BtcMuSig2NoncesRequest {
            input_index: 2,
            skip: false,
            context_key: metadata.context_key.clone(),
            tapleaf_hash: metadata.tapleaf_hash.clone(),
            nonces: context
                .participants
                .iter()
                .map(|key| pb::BtcMuSig2Nonce {
                    participant_pubkey: key.to_vec(),
                    public_nonce: vec![4; 66],
                })
                .collect(),
        };
        order_nonces(2, &metadata, &context, &request, None).unwrap();
        for mutation in 0..7 {
            let mut request = request.clone();
            match mutation {
                0 => request.input_index += 1,
                1 => request.context_key[1] ^= 1,
                2 => request.tapleaf_hash = None,
                3 => {
                    request.nonces.pop();
                }
                4 => request.nonces[1] = request.nonces[0].clone(),
                5 => request.nonces[1].participant_pubkey[1] ^= 1,
                _ => {
                    request.nonces[0].public_nonce.pop();
                }
            }
            assert!(order_nonces(2, &metadata, &context, &request, None).is_err());
        }
        // With our nonce supplied by the device, the request must carry exactly
        // the other participants' nonces.
        let ours = [7; 66];
        let mut others = request.clone();
        others
            .nonces
            .retain(|nonce| nonce.participant_pubkey.as_slice() != context.participant);
        let ordered = order_nonces(2, &metadata, &context, &others, Some(&ours)).unwrap();
        assert_eq!(ordered[0], ours);
        assert_eq!(ordered[1], [4; 66]);
        assert!(order_nonces(2, &metadata, &context, &request, Some(&ours)).is_err());
        others.nonces.clear();
        assert!(order_nonces(2, &metadata, &context, &others, Some(&ours)).is_err());
    }
}
