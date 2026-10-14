use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use std::env;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct CloudConfig {
    pub r2_account_id: Option<String>,
    pub r2_bucket_name: Option<String>,
    pub r2_access_key_id: Option<String>,
    pub r2_secret_access_key: Option<String>,
    pub r2_public_domain: Option<String>,
    pub supabase_url: Option<String>,
    pub supabase_key: Option<String>,
}

static CONFIG: OnceLock<CloudConfig> = OnceLock::new();
static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub fn init_cloud() {
    let _ = dotenvy::dotenv();
    let config = CloudConfig {
        r2_account_id: env::var("R2_ACCOUNT_ID").ok(),
        r2_bucket_name: env::var("R2_BUCKET_NAME").ok(),
        r2_access_key_id: env::var("R2_ACCESS_KEY_ID").ok(),
        r2_secret_access_key: env::var("R2_SECRET_ACCESS_KEY").ok(),
        r2_public_domain: env::var("R2_PUBLIC_DOMAIN").ok(),
        supabase_url: env::var("SUPABASE_URL").ok(),
        supabase_key: env::var("SUPABASE_SERVICE_ROLE_KEY").ok(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("Failed to create reqwest client");

    let _ = CONFIG.set(config.clone());
    let _ = HTTP_CLIENT.set(client);

    if config.supabase_url.is_some() && config.supabase_key.is_some() {
        println!("Supabase integration: ENABLED");
    } else {
        println!("Supabase integration: DISABLED (missing credentials in .env)");
    }

    if config.r2_account_id.is_some() && config.r2_access_key_id.is_some() {
        println!("Cloudflare R2 integration: ENABLED");
    } else {
        println!("Cloudflare R2 integration: DISABLED (missing credentials in .env)");
    }
}

pub fn get_config() -> &'static CloudConfig {
    CONFIG.get_or_init(|| CloudConfig {
        r2_account_id: None,
        r2_bucket_name: None,
        r2_access_key_id: None,
        r2_secret_access_key: None,
        r2_public_domain: None,
        supabase_url: None,
        supabase_key: None,
    })
}

fn client() -> &'static reqwest::Client {
    HTTP_CLIENT.get_or_init(|| reqwest::Client::new())
}

// ==========================================
// Cloudflare R2 Upload with AWS SigV4
// ==========================================

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn get_signature_key(key: &str, date_stamp: &str, region_name: &str, service_name: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region_name.as_bytes());
    let k_service = hmac_sha256(&k_region, service_name.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

pub async fn upload_to_r2(key: &str, payload: &[u8], content_type: &str) -> Result<String, String> {
    let cfg = get_config();
    let account_id = cfg.r2_account_id.as_deref().ok_or("Missing R2_ACCOUNT_ID")?;
    let bucket = cfg.r2_bucket_name.as_deref().ok_or("Missing R2_BUCKET_NAME")?;
    let access_key = cfg.r2_access_key_id.as_deref().ok_or("Missing R2_ACCESS_KEY_ID")?;
    let secret_key = cfg.r2_secret_access_key.as_deref().ok_or("Missing R2_SECRET_ACCESS_KEY")?;

    let host = format!("{account_id}.r2.cloudflarestorage.com");
    let region = "auto";
    let service = "s3";

    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let mut hasher = Sha256::new();
    hasher.update(payload);
    let payload_hash = hex::encode(hasher.finalize());

    // Canonical URI must start with /<bucket>/<key>
    let canonical_uri = format!("/{bucket}/{key}");
    let canonical_querystring = "";
    let canonical_headers = format!(
        "host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n"
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "PUT\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let mut req_hasher = Sha256::new();
    req_hasher.update(canonical_request.as_bytes());
    let canonical_request_hash = hex::encode(req_hasher.finalize());

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "{algorithm}\n{amz_date}\n{credential_scope}\n{canonical_request_hash}"
    );

    let signing_key = get_signature_key(secret_key, &date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization_header = format!(
        "{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );

    let url = format!("https://{host}/{bucket}/{key}");

    let mut headers = HeaderMap::new();
    headers.insert(
        "x-amz-date",
        HeaderValue::from_str(&amz_date).map_err(|e| e.to_string())?,
    );
    headers.insert(
        "x-amz-content-sha256",
        HeaderValue::from_str(&payload_hash).map_err(|e| e.to_string())?,
    );
    headers.insert(
        "Authorization",
        HeaderValue::from_str(&authorization_header).map_err(|e| e.to_string())?,
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_str(content_type).map_err(|e| e.to_string())?,
    );

    let res = client()
        .put(&url)
        .headers(headers)
        .body(payload.to_vec())
        .send()
        .await
        .map_err(|e| format!("R2 HTTP request failed: {e}"))?;

    if res.status().is_success() {
        let public_url = if let Some(domain) = &cfg.r2_public_domain {
            let base = domain.trim_end_matches('/');
            format!("{base}/{key}")
        } else {
            url
        };
        Ok(public_url)
    } else {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        Err(format!("R2 upload error (status {status}): {body}"))
    }
}

pub fn spawn_r2_upload(key: String, payload: Vec<u8>, content_type: String) {
    tokio::spawn(async move {
        match upload_to_r2(&key, &payload, &content_type).await {
            Ok(url) => println!("[Cloudflare R2] Successfully uploaded {key} -> {url}"),
            Err(e) => eprintln!("[Cloudflare R2] Upload failed for {key}: {e}"),
        }
    });
}

// ==========================================
// Supabase Sync (PostgREST Upsert)
// ==========================================

pub async fn upsert_supabase_visitor(visitor_data: &serde_json::Value) -> Result<(), String> {
    let cfg = get_config();
    let supabase_url = cfg.supabase_url.as_deref().ok_or("Missing SUPABASE_URL")?;
    let supabase_key = cfg.supabase_key.as_deref().ok_or("Missing SUPABASE_SERVICE_ROLE_KEY")?;

    let base = supabase_url.trim_end_matches('/');
    let url = format!("{base}/rest/v1/visitors?on_conflict=session_id");

    let mut headers = HeaderMap::new();
    headers.insert("apikey", HeaderValue::from_str(supabase_key).map_err(|e| e.to_string())?);
    headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {supabase_key}")).map_err(|e| e.to_string())?);
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    headers.insert("Prefer", HeaderValue::from_static("resolution=merge-duplicates,return=minimal"));

    let res = client()
        .post(&url)
        .headers(headers)
        .json(visitor_data)
        .send()
        .await
        .map_err(|e| format!("Supabase request failed: {e}"))?;

    if res.status().is_success() {
        Ok(())
    } else {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        Err(format!("Supabase upsert error (status {status}): {body}"))
    }
}

pub fn spawn_supabase_sync(visitor_data: serde_json::Value) {
    tokio::spawn(async move {
        let sid = visitor_data.get("session_id").and_then(|v| v.as_str()).unwrap_or("unknown");
        match upsert_supabase_visitor(&visitor_data).await {
            Ok(_) => println!("[Supabase] Synced visitor session: {sid}"),
            Err(e) => eprintln!("[Supabase] Sync failed for session {sid}: {e}"),
        }
    });
}

// ==========================================
// High-Accuracy Geolocation Resolver (ipwho.is)
// ==========================================

pub async fn resolve_ip_geo(ip: &str) -> Option<(String, String, String, String)> {
    let clean = ip.trim();
    if clean.is_empty()
        || clean.starts_with("127.")
        || clean == "::1"
        || clean.starts_with("192.168.")
        || clean.starts_with("10.")
    {
        return None;
    }

    let url = format!("https://ipwho.is/{clean}");
    let res = client().get(&url).send().await.ok()?;
    let json: serde_json::Value = res.json().await.ok()?;

    if json.get("success").and_then(|s| s.as_bool()).unwrap_or(false) {
        let city = json.get("city").and_then(|s| s.as_str()).unwrap_or("Abuja").to_string();
        let region = json.get("region").and_then(|s| s.as_str()).unwrap_or("Abuja Federal Capital Territory").to_string();
        let country = json.get("country").and_then(|s| s.as_str()).unwrap_or("Nigeria").to_string();
        let isp = json
            .get("connection")
            .and_then(|c| c.get("isp").or_else(|| c.get("org")))
            .and_then(|s| s.as_str())
            .unwrap_or("MTN Nigeria")
            .to_string();

        Some((city, region, country, isp))
    } else {
        None
    }
}
