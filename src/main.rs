use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
    },
    structures::{
        EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, PublicBuilder,
        PublicEccParametersBuilder, SymmetricDefinition,
    },
    Context, Tcti,
};

fn main() -> testresult::TestResult {
    let mut context = Context::new(Tcti::from_environment_variable()?)?;

    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
        )
        .expect("Failed to create session")
        .expect("Received invalid handle");
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context
        .tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
        .expect("Failed to set attributes on session");
    context.set_sessions((Some(session), None, None));

    let random = context.get_random(32)?;

    println!("Hello, world: {random:?}");

    let ecc_parms = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(false)
        .with_is_decryption_key(true)
        .with_restricted(false)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .unwrap();

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(false)
        .build()
        .unwrap();

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_parms)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .unwrap();
    let key_handle = context.create_primary(
        tss_esapi::interface_types::resource_handles::Hierarchy::Owner,
        public,
        None,
        None,
        None,
        None,
    )?;

    println!("Key handle: {:?}", key_handle.out_public);
    Ok(())
}
