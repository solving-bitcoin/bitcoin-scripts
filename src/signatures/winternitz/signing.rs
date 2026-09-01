use bitcoin::hex::DisplayHex;
use bitcoin::Witness;
use serde::{Deserialize, Serialize};

use crate::script::{script, Script};
use crate::{
    signatures::winternitz::{
        generate_public_key, BruteforceVerifier, ListpickVerifier, Parameters, PublicKey,
        SecretKey, ToBytesConverter, VoidConverter, Winternitz,
    },
    u32::u32_std::u32_compress,
};

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzSecret {
    pub secret_key: SecretKey,
    parameters: Parameters,
}

pub const LOG_D: u32 = 4;

pub const WINTERNITZ_MESSAGE_VERIFIER: Winternitz<ListpickVerifier, VoidConverter> =
    Winternitz::new();

pub const WINTERNITZ_VARIABLE_VERIFIER: Winternitz<ListpickVerifier, ToBytesConverter> =
    Winternitz::new();

pub const WINTERNITZ_MESSAGE_COMPACT_VERIFIER: Winternitz<BruteforceVerifier, VoidConverter> =
    Winternitz::new();

impl WinternitzSecret {
    pub fn new(message_len: usize) -> Self {
        let mut buffer = [0u8; 20];
        let mut rng = rand::rngs::OsRng;
        rand::RngCore::fill_bytes(&mut rng, &mut buffer);

        Self::from_bytes(message_len, buffer.to_lower_hex_string().into())
    }

    pub fn from_bytes(message_len: usize, secret_bytes: Vec<u8>) -> Self {
        let parameters = Parameters::new_by_bit_length(message_len as u32 * 8, LOG_D);
        Self {
            secret_key: secret_bytes,
            parameters,
        }
    }

    #[deprecated(note = "It is safer to use WinternitzSecret::from_bytes")]
    pub fn from_string(secret: &str, parameters: &Parameters) -> Self {
        WinternitzSecret {
            secret_key: secret.as_bytes().to_lower_hex_string().into(),
            parameters: *parameters,
        }
    }
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Hash, Clone)]
pub struct WinternitzPublicKey {
    pub public_key: PublicKey,
    pub parameters: Parameters,
}

impl From<&WinternitzSecret> for WinternitzPublicKey {
    fn from(secret: &WinternitzSecret) -> Self {
        WinternitzPublicKey {
            public_key: generate_public_key(&secret.parameters, &secret.secret_key),
            parameters: secret.parameters,
        }
    }
}

pub struct WinternitzSigningInputs<'a, 'b> {
    pub message: &'a [u8],
    pub signing_key: &'b WinternitzSecret,
}

pub fn generate_winternitz_checksig_leave_hash(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    script! {
        {WINTERNITZ_VARIABLE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)}
        for i in 1..message_size {
            {i} OP_ROLL
        }
    }
}

pub fn generate_winternitz_checksig_leave_variable(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    assert_eq!(message_size % 4, 0, "message should be u32s");
    let u32s_size = message_size / 4;
    script! {
        {WINTERNITZ_VARIABLE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)}
        for _ in 0..u32s_size {
            {u32_compress()}
            OP_TOALTSTACK
        }
        for _ in 0..u32s_size {
            OP_FROMALTSTACK
        }
        for i in 1..u32s_size {
            {i} OP_ROLL
        }
    }
}

pub fn generate_winternitz_witness(signing_inputs: &WinternitzSigningInputs) -> Witness {
    WINTERNITZ_MESSAGE_VERIFIER.sign(
        &signing_inputs.signing_key.parameters,
        &signing_inputs.signing_key.secret_key,
        signing_inputs.message,
    )
}

pub fn winternitz_message_checksig(public_key: &WinternitzPublicKey) -> Script {
    WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key)
}

pub fn winternitz_message_checksig_verify(
    public_key: &WinternitzPublicKey,
    message_size: usize,
) -> Script {
    script! {
        { WINTERNITZ_MESSAGE_VERIFIER.checksig_verify(&public_key.parameters, &public_key.public_key) }
        for _ in 0..message_size {
            OP_DROP
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{execute_script, signatures::utils};
    use bitcoin_script::script;

    const BLAKE3_HASH_LENGTH: usize = 20;

    #[test]
    fn test_signing_winternitz_with_message_success() {
        let secret = WinternitzSecret::new(4);
        let public_key = WinternitzPublicKey::from(&secret);
        let start_time_block_number = 860033_u32;

        let s = script! {
          { generate_winternitz_witness(
            &WinternitzSigningInputs {
              message: &start_time_block_number.to_le_bytes(),
              signing_key: &secret,
          },
          ).to_vec() }
          { winternitz_message_checksig(&public_key) }
          { utils::digits_to_number::<{ 4 * 2}, { LOG_D as usize }>() }
          { start_time_block_number }
          OP_EQUAL
        };

        let result = execute_script(s);
        assert!(result.success);
    }

    #[test]
    fn test_generate_winternitz_secret_length() {
        let secret = WinternitzSecret::new(1);
        assert_eq!(secret.secret_key.len(), 40);
    }

    #[test]
    fn test_winternitz_public_key_from_secret() {
        let secret = WinternitzSecret::new(BLAKE3_HASH_LENGTH);
        let public_key = WinternitzPublicKey::from(&secret);
        let reference_public_key = generate_public_key(&secret.parameters, &secret.secret_key);

        for i in 0..secret.parameters.total_digit_len() {
            assert_eq!(
                public_key.public_key[i as usize],
                reference_public_key[i as usize]
            );
        }
    }

    #[test]
    fn test_winternitz_public_key_from_secret_length() {
        let secret = WinternitzSecret::new(BLAKE3_HASH_LENGTH);
        let public_key = WinternitzPublicKey::from(&secret);

        assert_eq!(
            public_key.public_key.len(),
            public_key.parameters.total_digit_len() as usize
        );
        for i in 0..public_key.parameters.total_digit_len() {
            assert_eq!(public_key.public_key[i as usize].len(), 20);
        }
    }

}
