//! Port of Utils/auth-utils.test.ts.
use baileys::auth::AuthenticationCreds;
use baileys::types::Contact;
use baileys::utils::auth_utils::{assert_me_id, init_auth_creds};

fn creds_with_me(me: Option<Contact>) -> AuthenticationCreds {
    AuthenticationCreds { me, ..init_auth_creds() }
}
#[test]
fn t_assertmeid_returns_me_id_when_authenticated() {
    let creds = creds_with_me(Some(Contact::new("5511999999999@s.whatsapp.net")));
    assert_eq!(assert_me_id(&creds).unwrap(), "5511999999999@s.whatsapp.net");
}
#[test]
fn t_assertmeid_throws_boom_401_when_creds_me_is_undefined() {
    let creds = creds_with_me(None);
    let err = assert_me_id(&creds).unwrap_err();
    assert_eq!(err.output_status_code(), 401);
    assert!(err.message.contains("not authenticated"));
}
#[test]
fn t_assertmeid_throws_boom_401_when_me_has_no_id() {
    // adapted: `id` is a required String, and an empty string stands for a missing `id`
    let creds = creds_with_me(Some(Contact::default()));
    assert!(assert_me_id(&creds).unwrap_err().message.contains("not authenticated"));
}
#[test]
fn t_assertmeid_throws_boom_401_when_me_id_is_empty_string() {
    let creds = creds_with_me(Some(Contact::new("")));
    assert!(assert_me_id(&creds).unwrap_err().message.contains("not authenticated"));
}
