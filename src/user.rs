use chrono::Duration;
use ed25519_compact::{KeyPair, Seed};
use jwt_compact::{alg::*, prelude::*};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sthash::*;

/// This is something you need to create before deploying, generating this was a
/// massive pain in the ass https://www.random.org/cgi-bin/randbyte?nbytes=32&format=d
/// Doing it randomly / securely is hard.
/// Changing this to be pulled along with a KId from a secondary KV store would
/// be ideal for key rotation, but we're already pretty broken in terms of security
const JSON_SECRET_SEED: &'static [u8; 32] = &[
    241, 160, 112, 181, 215, 114, 171, 54, 203, 13, 221, 125, 180, 60, 142, 54, 142, 113, 71, 15,
    210, 216, 137, 140, 44, 40, 68, 134, 251, 241, 238, 103,
];
const SEED_ID: &'static str = "PLEASECHANGE";

/// This is the user structure that we are going to be storing the
/// global KV store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    password: String,
    pub token: String,
}

impl UserRecord {}

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct UserClaims {
    sub: String,
}

/// Validates a token using the given secret seed and returns a boolan if
/// the JWT was valid or not
/// 
/// Its entirely possible for the client to validate this JWT on its own, but
/// some clients will not have support for ED25519 so I'm exposing a first-party
/// validation endpoint for the token string
pub fn validate_jwt(token_string: String) -> Result<bool, String> {
    // We really cant create the keys easily ourselves because
    // they need to actually fall on the curve
    let seed = Seed::from_slice(JSON_SECRET_SEED).map_err(|e| e.to_string())?;
    let key_pair = KeyPair::from_seed(seed);
    // Parse the token.
    let token = UntrustedToken::new(&token_string).map_err(|e| e.to_string())?;
    // Validate the token integrity.
    match Ed25519.validate_integrity::<UserClaims, >(&token, &key_pair.pk){
        Ok(_) => return Ok(true),
        Err(err) => return Err(String::from(err.to_string()))
    };
}

/// Hash the password provided by the user and return the byte vector
/// that will be / was stored in the database.
pub fn hash_password(password: String, salt: String) -> String {
    // We're using the salt as a sort of initialization vector (encryption terminology)
    // for the data we want to hash, so we dont really need the personalization section
    // of the function call.
    let key = Key::from_seed(&salt.to_owned().as_bytes(), None);
    // Another personalization string, such as the purpose of the
    // `Hasher`, can be provided here as well.
    let hashed: Vec<u8> = Hasher::new(key, None).hash(&password.as_bytes());
    // A nicer way to store the password that wont cause any encoding/decoding troubles
    // when moving to the databases string representation
    let chars: Vec<String> = hashed.iter().map(|b| format!("{:02X}", b)).collect();
    chars.join("")
}

/// Creates the JWT from a username. The token is valid for 7 days and is signed using
/// HS256
fn create_jwt(username: String) -> Result<String, String> {
    // We really cant create the keys easily ourselves because
    // they need to actually fall on the curve
    let keyp = match Seed::from_slice(JSON_SECRET_SEED) {
        Ok(seed) => KeyPair::from_seed(seed),
        Err(_) => return Err(String::from("Bad seed")),
    };

    // This needs to be implemented in a WASM safe way later
    let header = Header::default().with_key_id(SEED_ID);
    // Choose time-related options for token creation / validation.
    let time_options = TimeOptions::default();
    let claims = Claims::new(UserClaims {
        sub: username.to_owned(),
    })
    .set_duration_and_issuance(&time_options, Duration::days(7));
    match Ed25519.token(header, &claims, &keyp.sk) {
        Ok(token) => Ok(token),
        Err(e) => Err(format!("Failed to create JSON Token - {}", e)),
    }
}

// Adding a U/P to the database
pub fn create_user_record(username: String, password: String) -> Result<UserRecord, String> {
    // Salts generally protect against rainbow table attacks on password databases,
    // and even though its very unlikely someone will find a way to dump the KV database
    // we're storing these passwords in, I'm gonna use a secure one anyway
    let salt: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let secure_pass = hash_password(password.to_owned(), salt.to_owned());
    // Finally we need to create the JWT that we can hand off to the client
    match create_jwt(username.to_owned()) {
        Ok(token) => Ok(UserRecord {
            username: username.clone(),
            password: format!("{}+{}", secure_pass.clone(), salt.clone()),
            token: token,
        }),
        Err(e) => Err(e),
    }
}

/// This is when a user does not already have a JWT and would like to get a new
/// one from the server using their U/P.
pub fn verify_login(
    username: String,
    password: String,
    user_record: UserRecord,
) -> Result<UserRecord, String> {
    let pass_and_salt: Vec<String> = user_record.password.split("+").map(String::from).collect();
    let hashed = hash_password(password.to_owned(), pass_and_salt[1].to_owned());
    if !pass_and_salt[0].eq(&hashed) {
        return Err(String::from("Bad Password"));
    }
    // Password is correct, update the jwt and return the user record
    // Finally we need to create the JWT that we can hand off to the client
    match create_jwt(username.to_owned()) {
        Ok(token) => Ok(UserRecord {
            username: username.clone(),
            password: user_record.password.to_owned(),
            token: token,
        }),
        Err(e) => Err(e),
    }
}
