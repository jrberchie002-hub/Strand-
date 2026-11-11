Strand: multi-shop platform for small sellers.

ENVIRONMENT VARIABLES (set in Vercel > Settings > Environment Variables)
  STORES_SECRET          Required. A long random secret, at least 32 characters. The site refuses to run in production without it.
  STORES_ADMIN           Your admin key, at least 16 characters. Open /admin and enter it. Without it the admin page is off.
  FIREBASE_PROJECT_ID    Needed for real use, so shops survive restarts. The project ID shown in Firebase console.
  FIREBASE_CLIENT_EMAIL  From a Firebase service account key (see below).
  FIREBASE_PRIVATE_KEY   From the same service account key. Paste it with real newlines, or with \n - either works.

  Without all three FIREBASE_* values set, Strand runs on in-memory storage only: it works for testing, but
  everything is wiped on every restart/redeploy. Get a service account key:
    1. Firebase console > your project > gear icon > Project settings > Service accounts.
    2. Click "Generate new private key" - downloads a JSON file. Keep it secret, never commit it.
    3. From that JSON, copy project_id into FIREBASE_PROJECT_ID, client_email into FIREBASE_CLIENT_EMAIL,
       and private_key into FIREBASE_PRIVATE_KEY.
    4. In the Firebase console, make sure Firestore (Native mode) is created for the project (Build > Firestore Database > Create database).
    5. Redeploy after adding the variables.
  Data lives in a single Firestore collection called "strand_kv" - one document per internal key. Nothing else
  needs to be created by hand.

MAIN DATABASE (optional: Supabase Postgres as the primary database, Firestore as a live backup)
  SUPABASE_DB_URL        A second Supabase project's URL, e.g. https://yyyy.supabase.co. Use a DIFFERENT
                          Supabase project/account than the one used for IMAGES below - keep them separate.
  SUPABASE_DB_KEY        That project's service_role secret key (Project Settings > API). Keep it secret.

  Without these two set, nothing changes - Firestore (or memory, if Firestore isn't set up either) stays the
  only database, exactly as described above. With them set, Supabase's Postgres becomes the PRIMARY database:
  every signup, order, product, setting - everything - is read from and written to Supabase first. Firestore,
  if also configured, is kept as a live mirror: every single write goes to Firestore too, right alongside
  Supabase, so it's always a current, trustworthy backup rather than a stale snapshot. If Supabase ever has a
  problem, reads automatically fall back to reading from the Firestore mirror instead, with no visible error
  to sellers or shoppers - it just keeps working off the backup until Supabase is healthy again. A failed
  Firestore mirror write is logged but never blocks or fails the actual request.

  Set up:
    1. Create a second, separate Supabase project (a different account from the one used for image storage,
       so a problem with one never affects the other).
    2. Open its SQL Editor and run this once:
         create table if not exists kv_store (
           key text primary key,
           value jsonb,
           updated_at timestamptz not null default now()
         );
         alter table kv_store enable row level security;
       (Row Level Security with no policies means only the service_role key - which bypasses RLS entirely -
       can read or write this table; nothing else can touch it, even by accident.)
    3. Project Settings > API > copy the Project URL into SUPABASE_DB_URL and the service_role key into
       SUPABASE_DB_KEY. Redeploy.
    4. If you already have real stores/orders in Firestore from before this was set up, run the migration
       script once (scripts/migrate-firestore-to-supabase.js) to copy everything across before relying on
       Supabase as primary - see that file's own instructions at the top. It only copies data in; it never
       deletes anything from Firestore, which is exactly what keeps Firestore usable as the backup afterwards.

PRIVATE FILES (optional: a second, non-public Supabase bucket - not wired into a feature yet)
  SUPABASE_PRIVATE_URL     Optional. Defaults to SUPABASE_URL (the images account) if not set.
  SUPABASE_PRIVATE_KEY     Optional. Defaults to SUPABASE_SERVICE_KEY if not set.
  SUPABASE_PRIVATE_BUCKET  Optional. Defaults to "strand-private" if not set.

  This is separate from "strand-images": that bucket is Public (anyone with a link can view a file in it,
  which is what product photos need). This one is for files that should NOT be viewable by just anyone with
  a link - create it in Supabase's Storage page with "Public bucket" left OFF. Nothing uploads here yet; the
  upload/signed-link/delete functions (privUpload/privSignedUrl/privDelete in api/index.js) are built and
  ready, waiting for a feature that needs private files (verification documents, exports, etc.) to use them.
  Reading a private file back always goes through privSignedUrl, which hands out a short-lived link (several
  minutes by default) rather than a permanent public one.

IMAGES (optional: Supabase Storage)
  SUPABASE_URL           Your first (primary) project's URL, e.g. https://xxxx.supabase.co.
  SUPABASE_SERVICE_KEY   That project's service_role secret key (Project Settings > API). Not the anon key -
                          the service_role key is required to upload. Keep it secret, never expose it to the browser.
  SUPABASE_BUCKET        Optional. The bucket name in the first account, if it isn't "strand-images" (default).
  SUPABASE_URL_2         Optional. A second Supabase project's URL, used only as a backup account.
  SUPABASE_SERVICE_KEY_2 Optional. That second project's service_role key.
  SUPABASE_BUCKET_2      Optional. The bucket name in the second account, if it isn't "strand-images" (default).

  Without any of these set, pictures are still accepted and stored exactly as before (inline, as base64 inside the
  shop's own record) - nothing breaks. With SUPABASE_URL/SUPABASE_SERVICE_KEY set, every picture a seller uploads
  (hero, banner, products) is instead pushed to a Supabase Storage bucket and the shop stores a normal https link
  to it - faster pages, and pictures stop counting against Firestore's 1 GiB free storage limit. Set up:
    1. In your Supabase project, go to Storage and create a bucket. Set it Public (so shoppers' browsers can load
       the pictures directly). If you name it exactly "strand-images" you don't need to set SUPABASE_BUCKET; if
       you gave it another name (bucket names can't be changed after creation), set SUPABASE_BUCKET to that name.
    2. Project Settings > API > copy the Project URL into SUPABASE_URL and the service_role key into
       SUPABASE_SERVICE_KEY.
    3. Redeploy. No table or schema needed, and no SQL/RLS policies either - uploads use the service_role key,
       which bypasses Row Level Security entirely, and a Public bucket serves reads to anyone with no policy
       needed. This only uses Storage, not the Supabase database.

  Using a second account as a backup: if you also set SUPABASE_URL_2/SUPABASE_SERVICE_KEY_2 (with its own bucket,
  public, name set via SUPABASE_BUCKET_2 if it isn't "strand-images"), the first account is always tried first;
  account 2 only gets used for an upload if account 1's upload fails for some reason (an outage, a quota issue,
  etc.) - so in normal operation account 2 sits idle as a safety net. A picture already saved on either account
  keeps working either way, since what's stored is just a plain https link to wherever it landed.

WHAT IS INSIDE
  Sellers sign up with a phone number OR an email (WhatsApp not required), pick what they sell and what they want to do.
  Seller admin: Home (sales and profit), Orders, Products, Stock, Market study, Apps (discount codes, delivery fee, status pictures,
  low-stock alerts, orders download), Settings (details, payments, look, team, security).
  Shoppers can browse by category at /explore. Verified shops show the awning badge (you switch it on in /admin).

SECURITY
  Passwords: scrypt with a random salt; weak and common passwords refused.
  Login: 5 wrong tries lock an account (15 minutes, doubling up to 24 hours), stored in the database so it holds across servers.
  Sessions: signed tokens that expire (14 days owner, 7 days staff), killed instantly by "log out of all devices" or a password change.
  Staff tokens die when the staff member is removed. Sellers see a log of recent sign-ins.
  Paystack keys are encrypted (AES-256-GCM) and never sent back to the browser.
  Headers: CSP, HSTS, no framing, no sniffing, locked-down permissions. Pictures limited to jpeg/png/webp and size capped.
  Bots: hidden honeypot fields, rate limits per IP and per shop, scanner shield on every request.

Do not share STORES_SECRET or STORES_ADMIN. Rotate them if you think they leaked (everyone is signed out when STORES_SECRET changes).

More settings (all optional)
  PAYSTACK_PLATFORM_KEY  take plan payments by card/MoMo
  PRICE_PRO, PRICE_EXPERT  monthly prices
  RESEND_API_KEY, MAIL_FROM  email alerts
  VERCEL_TOKEN, VERCEL_PROJECT_ID  add custom domains automatically

Link to the command center (Neutron), automatic
  1. In Neutron, make a new stack and copy its link code (starts with NTR1.).
  2. In this project's Vercel settings add NEUTRON_LINK_CODE = that code, and SITE_URL = your https address (no slash at the end).
  3. Redeploy. The first visit links it; no pasting anywhere else.
  Neutron can then read a report and send: notice.set/clear, maint.on/off, shop.open/close/verify/unverify, plan.set.
