extern crate base64;
use base64::encode;
use hmacsha::HmacSha;
use hmacsha::ShaTypes;
use percent_encoding::{percent_encode, AsciiSet, NON_ALPHANUMERIC};
use reqwest::header::CONTENT_TYPE;
use std::time::{SystemTime, UNIX_EPOCH};
use textnonce::TextNonce;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const FRAGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'_')
    .remove(b'.')
    .remove(b'-')
    .remove(b'~');

pub struct SigningKey {
    consumer_secret: String,
    token_secret: String,
}

impl SigningKey {
    pub fn new(consumer_secret: &str, token_secret: &str) -> Self {
        Self {
            consumer_secret: consumer_secret.to_string(),
            token_secret: token_secret.to_string(),
        }
    }
    fn sign_signature(&self, signature: String) -> String {
        let key = format!(
            "{}&{}",
            percent_encode(self.consumer_secret.as_bytes(), FRAGMENT),
            percent_encode(self.token_secret.as_bytes(), FRAGMENT)
        );

        let mut hasher = HmacSha::from(&key, &signature, &ShaTypes::Sha1);
        let result = hasher.compute_digest();
        encode(result)
    }
}

struct Signature {
    method: String,
    url: String,
    parameter_str: String,
}

impl Signature {
    pub fn new(method: String, url: String, parameter_str: String) -> Self {
        Signature {
            method: method.to_uppercase(),
            url,
            parameter_str,
        }
    }

    pub fn get_signature_string(&self) -> String {
        format!(
            "{}&{}&{}",
            self.method,
            percent_encode(self.url.as_bytes(), FRAGMENT),
            percent_encode(self.parameter_str.as_bytes(), FRAGMENT)
        )
    }
}

fn generate_nonce() -> String {
    TextNonce::new().to_string()
    // "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg".to_string()
}

fn generate_timestamp() -> String {
    let seconds = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    seconds.as_secs().to_string()
    // "1318622958".to_string()
}

pub struct TwitterApi {
    oauth_consumer_key: String,
    oauth_token: String,
    signing: SigningKey,
}

impl TwitterApi {
    pub fn new(oauth_consumer_key: &str, oauth_token: &str, signing: SigningKey) -> Self {
        Self {
            oauth_consumer_key: oauth_consumer_key.to_string(),
            oauth_token: oauth_token.to_string(),
            signing,
        }
    }

    pub fn tweet(&self, msg: &str) -> Result<String> {
        let nonce = generate_nonce();
        let timestamp = generate_timestamp();

        let encoded_data = self.encode_data(msg, &nonce, &timestamp);
        let sig = Signature::new(
            "post".to_string(),
            "https://api.twitter.com/1.1/statuses/update.json".to_string(),
            encoded_data.clone(),
        );
        let signature = sig.get_signature_string();
        let signed_signature = self.signing.sign_signature(signature);

        let oauth_header = self.create_oauth_header(&signed_signature, &nonce, &timestamp);

        let client = reqwest::blocking::Client::new();
        let status_url = percent_encode(msg.as_bytes(), FRAGMENT).to_string();

        let result = client
            .post("https://api.twitter.com/1.1/statuses/update.json?include_entities=true")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("Authorization", oauth_header)
            .body(format!("status={}", status_url))
            .send()?;

        Ok(result.text()?)
    }

    fn encode_data(&self, msg: &str, nonce: &str, timestamp: &str) -> String {
        let mut params: Vec<(&str, &str)> = Vec::new();

        params.push(("include_entities", "true"));
        params.push(("oauth_nonce", nonce));
        params.push(("oauth_signature_method", "HMAC-SHA1"));
        params.push(("oauth_timestamp", timestamp));
        params.push(("oauth_version", "1.0"));
        params.push(("oauth_token", &self.oauth_token));
        params.push(("oauth_consumer_key", &self.oauth_consumer_key));
        params.push(("status", msg));

        let mut output: Vec<String> = params
            .into_iter()
            .map(|e| {
                format!(
                    "{}={}",
                    percent_encode(e.0.as_bytes(), FRAGMENT),
                    percent_encode(e.1.as_bytes(), FRAGMENT)
                )
            })
            .collect::<Vec<String>>();

        output.sort();
        output.join("&")
    }

    fn create_oauth_header(&self, signature: &str, nonce: &str, timestamp: &str) -> String {
        format!(
            r#"OAuth oauth_consumer_key="{}", oauth_nonce="{}", oauth_signature="{}", oauth_signature_method="{}", oauth_timestamp="{}", oauth_token="{}", oauth_version="{}""#,
            percent_encode(self.oauth_consumer_key.as_bytes(), FRAGMENT),
            percent_encode(nonce.as_bytes(), FRAGMENT),
            percent_encode(signature.as_bytes(), FRAGMENT),
            percent_encode("HMAC-SHA1".as_bytes(), FRAGMENT),
            percent_encode(timestamp.as_bytes(), FRAGMENT),
            percent_encode(self.oauth_token.as_bytes(), FRAGMENT),
            percent_encode("1.0".as_bytes(), FRAGMENT)
        )
    }
}
