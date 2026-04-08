// Copyright 2025 Irreducible Inc.
use std::{array, iter};

use anyhow::Result;
use binius_circuits::{
	bignum::BigUint, ecdsa::ecrecover, fixed_byte_vec::ByteVec, sha256::Sha256,
};
use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller, util::pack_bytes_into_wires_le};
use clap::Args;
use ethsign::SecretKey;
use rand::{Rng, SeedableRng, rngs::StdRng};
use sha2::{Digest, Sha256 as NativeSha256};

use crate::ExampleCircuit;

struct Signature {
	r: [Wire; 4],
	s: [Wire; 4],
	recid_odd: Wire,
	address: [Wire; 3],
	msg_sha256: Sha256,
	address_sha256: Sha256,
}

/// Example circuit that proves validity of ECDSA signatures using SHA-256.
pub struct Sha256SignExample {
	max_msg_len_bytes: usize,
	signatures: Vec<Signature>,
}

#[derive(Args, Debug, Clone)]
pub struct Params {
	/// Number of ECDSA signatures to validate
	#[arg(short = 'n', long, default_value_t = 1)]
	pub n_signatures: usize,
	/// Maximum message length
	#[arg(short = 'm', long, default_value_t = 128, value_parser = clap::value_parser!(u16).range(1..))]
	pub max_msg_len_bytes: u16,
}

#[derive(Args, Debug, Clone)]
pub struct Instance {}

impl ExampleCircuit for Sha256SignExample {
	type Params = Params;
	type Instance = Instance;

	fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
		let max_msg_len_bytes = params.max_msg_len_bytes as usize;
		let signatures = (0..params.n_signatures)
			.map(|_| {
				let msg_len = builder.add_inout();
				let message = (0..params.max_msg_len_bytes.div_ceil(8))
					.map(|_| builder.add_inout())
					.collect::<Vec<_>>();
				let r = array::from_fn(|_| builder.add_inout());
				let s = array::from_fn(|_| builder.add_inout());
				let recid_odd = builder.add_inout();
				let address = array::from_fn(|_| builder.add_inout());

				let msg_final_state = array::from_fn(|_| builder.add_witness());
				let msg_sha256 = Sha256::new(builder, msg_len, msg_final_state, message.clone());

				// The SHA-256 digest is big-endian encoded into 4 words. Reversing gives
				// little-endian limb order for BigUint (no byteswap needed).
				let z = BigUint {
					limbs: msg_final_state[..4].iter().rev().copied().collect(),
				};

				// Encoding r & s in little endian
				let public_key = ecrecover(
					builder,
					&z,
					&BigUint { limbs: r.to_vec() },
					&BigUint { limbs: s.to_vec() },
					recid_odd,
				);

				// Check that public key is not a point-at-infinity
				builder.assert_false("recovered_pk_not_pai", public_key.is_point_at_infinity);

				// Concatenate x & y in _big_ endian, hash the result to obtain the address
				let mut public_key_limbs = Vec::with_capacity(8);
				public_key_limbs.extend(&public_key.y.limbs);
				public_key_limbs.extend(&public_key.x.limbs);
				public_key_limbs.reverse();

				// Convert LE-packed BigUint limbs to SHA-256's two-BE-word message wire format
				// by rotating each 64-bit word by 32 bits.
				let public_key_message = public_key_limbs
					.into_iter()
					.map(|word| builder.rotl(word, 32))
					.collect::<Vec<_>>();

				let address_final_state = array::from_fn(|_| builder.add_witness());
				let address_sha256 = Sha256::new(
					builder,
					builder.add_constant_64(64),
					address_final_state,
					public_key_message,
				);

				// Assert that the provided address equals digest bytes 12..32
				// SHA-256 digest is BE-packed, convert to LE for ByteVec
				let address_digest_le = address_sha256.digest_to_le_wires(builder);
				assert_address_eq(builder, &address_digest_le, &address);

				Signature {
					r,
					s,
					recid_odd,
					address,

					msg_sha256,
					address_sha256,
				}
			})
			.collect();

		Ok(Self {
			signatures,
			max_msg_len_bytes,
		})
	}

	fn populate_witness(&self, _instance: Instance, w: &mut WitnessFiller) -> Result<()> {
		// Generate random initial state with fixed seed for reproducibility
		let mut rng = StdRng::seed_from_u64(42);

		for Signature {
			r,
			s,
			recid_odd,
			address,
			msg_sha256,
			address_sha256,
		} in &self.signatures
		{
			// Random private key
			let sk_bytes: [u8; 32] = rng.random();
			let secret_key = SecretKey::from_raw(&sk_bytes)?;

			// Random message
			let msg_len = rng.random_range(1..=self.max_msg_len_bytes);
			let msg_bytes = (0..msg_len).map(|_| rng.random()).collect::<Vec<u8>>();
			let msg_hash = sha256_hash(&msg_bytes);

			// Sign the message with ECDSA
			let mut signature = secret_key.sign(&msg_hash)?;
			let public = secret_key.public();

			// Hash the message with SHA-256
			msg_sha256.populate_len_bytes(w, msg_len);
			msg_sha256.populate_message(w, &msg_bytes);
			msg_sha256.populate_digest(w, msg_hash);

			// ethsign crate returns 0/1 recid, convert to `recid_odd` boolean
			w[*recid_odd] = if signature.v != 0 {
				Word::ALL_ONE
			} else {
				Word::ZERO
			};

			// ethsign crate returns r & s big endian, byteswap
			signature.r.reverse();
			pack_bytes_into_wires_le(w, r, &signature.r);

			signature.s.reverse();
			pack_bytes_into_wires_le(w, s, &signature.s);

			// Hash the (big endian) public key
			let pk_bytes = public.bytes();
			let pk_hash = sha256_hash(pk_bytes);

			address_sha256.populate_len_bytes(w, 64);
			address_sha256.populate_message(w, pk_bytes);
			address_sha256.populate_digest(w, pk_hash);

			// Derive address from SHA-256 hash of public key (bytes 12..32)
			let address_bytes: &[u8] = &pk_hash[12..32];
			pack_bytes_into_wires_le(w, address, address_bytes);
		}

		Ok(())
	}

	fn param_summary(params: &Self::Params) -> Option<String> {
		Some(format!("{}s-{}b", params.n_signatures, params.max_msg_len_bytes))
	}
}

fn assert_address_eq(b: &CircuitBuilder, digest: &[Wire], address: &[Wire]) {
	assert_eq!(digest.len(), 4);
	assert_eq!(address.len(), 3);

	let digest_len = b.add_constant_64(32);
	let digest_byte_vec = ByteVec::new(digest.to_vec(), digest_len);
	let digest_sliced = digest_byte_vec.slice_const_range(b, 12..32);

	for (i, (&lhs_i, rhs_i)) in iter::zip(address, digest_sliced.data).enumerate() {
		b.assert_eq(format!("address_word_{i}"), lhs_i, rhs_i);
	}
}

fn sha256_hash(bytes: &[u8]) -> [u8; 32] {
	NativeSha256::digest(bytes).into()
}
