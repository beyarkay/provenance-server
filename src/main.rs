#[macro_use]
extern crate rocket;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use ed25519_dalek::SigningKey;
use rocket::{request::FromParam, State};
use serde::Serialize;
use std::{collections::HashMap, sync::Mutex};

use rocket::serde::json::Json;

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
struct Username(String);

impl<'r> FromParam<'r> for Username {
    type Error = &'r str;

    fn from_param(param: &'r str) -> Result<Self, Self::Error> {
        Ok(Username(param.to_string()))
    }
}

// #[rocket::async_trait]
// impl<'r> FromRequest<'r> for Username {
//     type Error = String;
//     async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
//         match req.uri().path().split("/").last() {
//             None => Outcome::Error((Status::BadRequest, "No username provided".to_string())),
//             Some(username) => Outcome::Success(Username(username.to_string())),
//         }
//     }
// }

struct AppState {
    db: Mutex<HashMap<Username, SigningKey>>,
}

#[derive(Default, Debug, Serialize)]
pub struct KeyDetails {
    pub public: String,
    pub private: String,
}

#[derive(Default, Debug, Serialize)]
pub struct SignerDetails {
    pub verification_url: String,
    pub verification_key: String,
    pub metadata: HashMap<String, String>,
}

#[get("/generate_key/<username>")]
fn generate_key(username: Username, state: &State<AppState>) -> Result<Json<KeyDetails>, String> {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let user_exists = state.db.lock().unwrap().contains_key(&username);
    if user_exists {
        return Err(format!("Username {:?} already exists", username.0));
    }
    state
        .db
        .lock()
        .unwrap()
        .insert(username, signing_key.clone());

    let public_b64 = URL_SAFE.encode(signing_key.verifying_key().to_bytes());
    let private_b64 = URL_SAFE.encode(signing_key.to_bytes());

    Ok(Json(KeyDetails {
        public: public_b64,
        private: private_b64,
    }))
}

#[get("/provenance/<username>")]
fn provenance(username: Username, state: &State<AppState>) -> Result<Json<SignerDetails>, String> {
    let base_url = "http://127.0.0.1:8000";

    let binding = state.db.lock().unwrap();
    let Some(signing_key) = binding.get(&username) else {
        return Err(format!("Username {:?} not found", username.0));
    };
    let verification_key_b64 = URL_SAFE.encode(signing_key.verifying_key().to_bytes());

    let mut metadata: HashMap<String, String> = HashMap::new();
    metadata.insert("username".to_string(), username.clone().0);

    Ok(Json(SignerDetails {
        verification_url: format!("{base_url}/{}/provenance", username.0),
        verification_key: verification_key_b64,
        metadata,
    }))
}

#[launch]
fn rocket() -> _ {
    let db = Mutex::new(HashMap::new());
    let state = AppState { db };

    rocket::build()
        .manage(state)
        .mount("/", routes![provenance, generate_key])
}
