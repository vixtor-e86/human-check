# human-check

Self-hosted "Verify you are human" challenge with Image CAPTCHA + Face Liveness in Rust (Axum).

    cargo run          # then open http://localhost:3000

## Verification Flow
1. **Landing Page Load**: The user opens the site and views the enterprise landing page.
2. **1-Second Overlay Barrier**: In exactly 1 second, a frosted translucent overlay locks the screen and presents:
   - **Stage 1 (Image CAPTCHA)**: Spatial challenge selecting matching tiles.
   - **Stage 2 (Face Liveness)**: Biometric window capturing 5 FPS video frames with interactive **Nod &rarr; Turn &rarr; Blink** prompts.
3. **Session Unlock**: Upon passing both stages, the barrier dissolves and the entire landing page is unlocked for interaction.

## Biometric Data Capture & Supabase-Ready SQLite Database
* **Lightweight Schema**: Kept strictly to the `visitors` table in SQLite (`data/human_check.db`) without frame-by-frame database bloat, making it instant to sync with Supabase tables.
* **Cloudflare Storage Isolation**: Captured frames are stored as JPEG files on disk (`captures/<ip>_<time>_<id>/`), ready for direct batch pushing to Cloudflare R2 object storage.
* **Immediate Visitor Tracking**: Records IP, geolocation (country, city, ISP), timestamp, browser, OS, and screen resolution immediately upon entry.

## Intelligence Dashboard
* Open **http://localhost:3000/admin** to view:
  * Total visitor metrics and verification rates.
  * Real-time visitor logs with IP addresses, geographic locations, and devices.
  * Interactive image gallery to preview all captured biometric face frames.

Use real photos: drop .jpg/.png/.webp files into images/train, images/bus,
images/car, images/bicycle. Any folder with files is used instead of the
built-in vector art. Add a category by adding it to CATEGORIES in src/main.rs.

Integrate: after the browser gets a token, your backend POSTs
{"token": "..."} to /api/siteverify and checks {"success": true}.
