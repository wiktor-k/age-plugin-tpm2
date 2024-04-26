#![doc = include_str!("../README.md")]

use std::collections::HashMap;
use std::io;

use age_core::{
    format::FILE_KEY_BYTES,
    primitives::{aead_decrypt, hkdf},
    secrecy::ExposeSecret,
};
use age_core::{
    format::{FileKey, Stanza},
    secrecy::Zeroize as _,
};
use age_plugin::{
    identity::{self, IdentityPluginV1},
    recipient::{self, RecipientPluginV1},
    run_state_machine, Callbacks,
};
use bech32::{ToBase32, Variant};
use clap::Parser;
use subtle::ConstantTimeEq;
use testresult::TestResult;
use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    },
    structures::{
        CreateKeyResult, CreatePrimaryKeyResult, EccParameter, EccPoint, EccScheme, HashScheme,
        KeyDerivationFunctionScheme, Public, PublicBuilder, PublicEccParametersBuilder,
        SymmetricDefinition,
    },
    Context, Tcti,
};

// Use lower-case HRP to avoid https://github.com/rust-bitcoin/rust-bech32/issues/40
const IDENTITY_PREFIX: &str = "age-plugin-tpm2-";
const PUBLIC_KEY_PREFIX: &str = "age";
const PLUGIN_NAME: &str = "tpm2";

pub const RECIPIENT_TAG: &str = "p256";
const RECIPIENT_KEY_LABEL: &[u8] = b"age-encryption.org/v1/p256";

pub const EPK_LEN_BYTES: usize = 64;
pub const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;
struct RecipientPlugin;

impl RecipientPluginV1 for RecipientPlugin {
    fn add_recipient(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn add_identity(
        &mut self,
        _index: usize,
        _plugin_name: &str,
        _bytes: &[u8],
    ) -> Result<(), recipient::Error> {
        todo!()
    }

    fn wrap_file_keys(
        &mut self,
        _file_keys: Vec<FileKey>,
        _callbacks: impl Callbacks<recipient::Error>,
    ) -> io::Result<Result<Vec<Vec<Stanza>>, Vec<recipient::Error>>> {
        todo!()
    }
}

struct CardStub {
    ident: String,
}

struct IdentityPlugin {
    cards: Vec<CardStub>,
}

use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
pub(crate) fn base64_arg<A: AsRef<[u8]>, const N: usize, const B: usize>(
    arg: &A,
) -> Option<[u8; N]> {
    if N > B {
        return None;
    }

    let mut buf = [0; B];
    match BASE64_STANDARD_NO_PAD.decode_slice(arg, buf.as_mut()) {
        Ok(n) if n == N => Some(buf[..N].try_into().unwrap()),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
enum DecryptError {
    #[error("Invalid header")]
    InvalidHeader,
    #[error("Card does not contain ECC key")]
    NonEccCard,
}

impl IdentityPlugin {
    fn unwrap_stanza(
        &mut self,
        stanza: &Stanza,
        callbacks: &mut impl Callbacks<identity::Error>,
    ) -> Result<Option<FileKey>, Box<dyn std::error::Error>> {
        if stanza.tag != RECIPIENT_TAG {
            return Err(std::io::Error::other("bad stanza tag").into());
        }

        // Enforce valid and canonical stanza format.
        // https://c2sp.org/age#x25519-recipient-stanza
        let ephemeral_share = match &stanza.args[..] {
            [arg] => match base64_arg::<_, EPK_LEN_BYTES, 33>(arg) {
                Some(ephemeral_share) => ephemeral_share,
                None => return Err(DecryptError::InvalidHeader.into()),
            },
            _ => return Err(DecryptError::InvalidHeader.into()),
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Err(DecryptError::InvalidHeader.into());
        }

        let encrypted_file_key: [u8; ENCRYPTED_FILE_KEY_BYTES] = stanza.body[..]
            .try_into()
            .expect("Length should have been checked above");

        let mut context = get_context()?;
        let key = get_key(&mut context)?;
        let z_value = context.ecdh_z_gen(
            key.key_handle,
            EccPoint::new(
                EccParameter::from_bytes(&ephemeral_share[0..32])?,
                EccParameter::from_bytes(&ephemeral_share[32..64])?,
            ),
        )?;
        let shared_secret = z_value.x();

        if shared_secret
            .iter()
            .fold(0, |acc, b| acc | b)
            .ct_eq(&0)
            .into()
        {
            return Err(DecryptError::InvalidHeader.into());
        }

        let mut salt = [0; 64];
        salt[..32].copy_from_slice(&ephemeral_share);
        if let Public::Ecc { unique, .. } = key.out_public {
            salt[32..].copy_from_slice(&unique.x()[..]);
        }

        let enc_key = hkdf(&salt, RECIPIENT_KEY_LABEL, &shared_secret);

        // A failure to decrypt is non-fatal (we try to decrypt the recipient
        // stanza with other X25519 keys), because we cannot tell which key
        // matches a particular stanza.
        if let Some(result) = aead_decrypt(&enc_key, FILE_KEY_BYTES, &encrypted_file_key)
            .ok()
            .map(|mut pt| {
                // It's ours!
                let file_key: [u8; FILE_KEY_BYTES] = pt[..].try_into().unwrap();
                pt.zeroize();
                FileKey::from(file_key)
            })
        {
            return Ok(Some(result));
        }
        Ok(None)
    }
}

impl IdentityPluginV1 for IdentityPlugin {
    fn add_identity(
        &mut self,
        index: usize,
        plugin_name: &str,
        bytes: &[u8],
    ) -> Result<(), identity::Error> {
        if plugin_name == PLUGIN_NAME {
            self.cards.push(CardStub {
                ident: String::from_utf8_lossy(bytes).to_string(),
            });
            Ok(())
        } else {
            Err(identity::Error::Identity {
                index,
                message: "invalid recipient".into(),
            })
        }
    }

    fn unwrap_file_keys(
        &mut self,
        files: Vec<Vec<Stanza>>,
        mut callbacks: impl Callbacks<identity::Error>,
    ) -> io::Result<HashMap<usize, Result<FileKey, Vec<identity::Error>>>> {
        let mut file_keys = HashMap::with_capacity(files.len());
        for (file_index, stanzas) in files.iter().enumerate() {
            for (stanza_index, stanza) in stanzas.iter().enumerate() {
                match self.unwrap_stanza(stanza, &mut callbacks).map_err(|e| {
                    vec![identity::Error::Stanza {
                        file_index,
                        stanza_index,
                        message: e.to_string(),
                    }]
                }) {
                    Ok(Some(file_key)) => {
                        file_keys.entry(file_index).or_insert(Ok(file_key));
                    }

                    Err(error) => {
                        file_keys.entry(file_index).or_insert(Err(error));
                    }
                    _ => {}
                }
            }
        }

        Ok(file_keys)
    }
}

#[derive(Debug, Parser)]
struct PluginOptions {
    #[arg(help = "run the given age plugin state machine", long)]
    age_plugin: Option<String>,
}

fn main() -> TestResult {
    let opts = PluginOptions::parse();

    if let Some(state_machine) = opts.age_plugin {
        return Ok(run_state_machine(
            &state_machine,
            Some(|| RecipientPlugin),
            Some(|| IdentityPlugin { cards: vec![] }),
        )?);
    }

    let mut context = get_context()?;
    let mut key = get_key(&mut context)?;

    if let Public::Ecc { unique, .. } = key.out_public {
        println!(
            "# {}",
            bech32::encode(PUBLIC_KEY_PREFIX, unique.x().to_base32(), Variant::Bech32)?
        );
    }

    println!(
        "{}",
        bech32::encode(IDENTITY_PREFIX, [1, 2, 3].to_base32(), Variant::Bech32,)?.to_uppercase()
    );
    println!();

    Ok(())
}

fn get_context() -> tss_esapi::Result<Context> {
    let mut context = Context::new(Tcti::from_environment_variable()?)?;

    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
        )?
        .expect("auth session");
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;
    context.set_sessions((Some(session), None, None));

    Ok(context)
}

fn get_key(context: &mut Context) -> tss_esapi::Result<CreatePrimaryKeyResult> {
    let ecc_parms = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()?;

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(false)
        .build()?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_parms)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()?;

    let key_handle = context.create_primary(
        tss_esapi::interface_types::resource_handles::Hierarchy::Owner,
        public,
        None,
        None,
        None,
        None,
    )?;

    Ok(key_handle)
}
