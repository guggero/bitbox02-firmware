// SPDX-License-Identifier: Apache-2.0

//! Bindings to the MuSig2 ABI in bitbox-secp256k1/depend/secp256k1-zkp.
//! The C library is built and linked by bitbox-secp256k1.
#![no_std]
#![allow(non_camel_case_types)]

use bitcoin::secp256k1::ffi::{Context, Keypair, PublicKey, XOnlyPublicKey};
use core::ffi::c_int;

#[repr(C)]
pub struct secp256k1_musig_keyagg_cache {
    pub data: [u8; 197],
}

#[repr(C)]
pub struct secp256k1_musig_secnonce {
    pub data: [u8; 132],
}

#[repr(C)]
pub struct secp256k1_musig_pubnonce {
    pub data: [u8; 132],
}

#[repr(C)]
pub struct secp256k1_musig_aggnonce {
    pub data: [u8; 132],
}

#[repr(C)]
pub struct secp256k1_musig_session {
    pub data: [u8; 133],
}

#[repr(C)]
pub struct secp256k1_musig_partial_sig {
    pub data: [u8; 36],
}

impl zeroize::Zeroize for secp256k1_musig_secnonce {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

unsafe extern "C" {
    pub fn secp256k1_musig_pubnonce_parse(
        ctx: *const Context,
        nonce: *mut secp256k1_musig_pubnonce,
        in66: *const u8,
    ) -> c_int;
    pub fn secp256k1_musig_pubnonce_serialize(
        ctx: *const Context,
        out66: *mut u8,
        nonce: *const secp256k1_musig_pubnonce,
    ) -> c_int;
    pub fn secp256k1_musig_pubkey_agg(
        ctx: *const Context,
        scratch: *mut core::ffi::c_void,
        agg_pk: *mut XOnlyPublicKey,
        keyagg_cache: *mut secp256k1_musig_keyagg_cache,
        pubkeys: *const *const PublicKey,
        n_pubkeys: usize,
    ) -> c_int;
    pub fn secp256k1_musig_pubkey_get(
        ctx: *const Context,
        agg_pk: *mut PublicKey,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
    ) -> c_int;
    pub fn secp256k1_musig_pubkey_ec_tweak_add(
        ctx: *const Context,
        output_pubkey: *mut PublicKey,
        keyagg_cache: *mut secp256k1_musig_keyagg_cache,
        tweak32: *const u8,
    ) -> c_int;
    pub fn secp256k1_musig_pubkey_xonly_tweak_add(
        ctx: *const Context,
        output_pubkey: *mut PublicKey,
        keyagg_cache: *mut secp256k1_musig_keyagg_cache,
        tweak32: *const u8,
    ) -> c_int;
    pub fn secp256k1_musig_nonce_gen(
        ctx: *const Context,
        secnonce: *mut secp256k1_musig_secnonce,
        pubnonce: *mut secp256k1_musig_pubnonce,
        session_id32: *const u8,
        seckey: *const u8,
        pubkey: *const PublicKey,
        msg32: *const u8,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
        extra_input32: *const u8,
    ) -> c_int;
    pub fn secp256k1_musig_nonce_agg(
        ctx: *const Context,
        aggnonce: *mut secp256k1_musig_aggnonce,
        pubnonces: *const *const secp256k1_musig_pubnonce,
        n_pubnonces: usize,
    ) -> c_int;
    pub fn secp256k1_musig_nonce_process(
        ctx: *const Context,
        session: *mut secp256k1_musig_session,
        aggnonce: *const secp256k1_musig_aggnonce,
        msg32: *const u8,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
        adaptor: *const PublicKey,
    ) -> c_int;
    pub fn secp256k1_musig_partial_sign(
        ctx: *const Context,
        partial_sig: *mut secp256k1_musig_partial_sig,
        secnonce: *mut secp256k1_musig_secnonce,
        keypair: *const Keypair,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
        session: *const secp256k1_musig_session,
    ) -> c_int;
    pub fn secp256k1_musig_partial_sig_verify(
        ctx: *const Context,
        partial_sig: *const secp256k1_musig_partial_sig,
        pubnonce: *const secp256k1_musig_pubnonce,
        pubkey: *const PublicKey,
        keyagg_cache: *const secp256k1_musig_keyagg_cache,
        session: *const secp256k1_musig_session,
    ) -> c_int;
    pub fn secp256k1_musig_partial_sig_serialize(
        ctx: *const Context,
        out32: *mut u8,
        sig: *const secp256k1_musig_partial_sig,
    ) -> c_int;
}

unsafe extern "C" {
    pub fn secp256k1_musig_partial_sig_parse(
        ctx: *const Context,
        signature: *mut secp256k1_musig_partial_sig,
        bytes: *const u8,
    ) -> c_int;
}
