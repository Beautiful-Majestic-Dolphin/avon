#![allow(clippy::unwrap_used)]
use avon_control::authz::{principal_of, require_service, session_token, Principal};
use base64ct::Encoding;
use tonic::metadata::MetadataValue;
use tonic::Request;

#[test]
fn request_without_tls_is_anonymous_and_rejected() {
    let req = Request::new(());
    assert!(matches!(principal_of(&req), Principal::Anonymous));
    let err = require_service(&req, &["gateway"]).unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[test]
fn session_token_metadata_is_decoded() {
    let mut req = Request::new(());
    let token = [7u8; 32];
    let encoded = base64ct::Base64UrlUnpadded::encode_string(&token);
    req.metadata_mut()
        .insert("x-avon-session", MetadataValue::try_from(encoded).unwrap());
    assert_eq!(session_token(&req).unwrap(), token);
    let mut bad = Request::new(());
    bad.metadata_mut().insert(
        "x-avon-session",
        MetadataValue::try_from("not-base64!").unwrap(),
    );
    assert_eq!(
        session_token(&bad).unwrap_err().code(),
        tonic::Code::Unauthenticated
    );
}
