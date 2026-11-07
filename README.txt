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

IMAGES (optional: Supabase Storage)
  SUPABASE_URL           Your project's URL, e.g. https://xxxx.supabase.co.
  SUPABASE_SERVICE_KEY   The project's service_role secret key (Project Settings > API). Not the anon key -
                          the service_role key is required to upload. Keep it secret, never expose it to the browser.

  Without these two set, pictures are still accepted and stored exactly as before (inline, as base64 inside the
  shop's own record) - nothing breaks. With them set, every picture a seller uploads (hero, banner, products) is
  instead pushed to a Supabase Storage bucket and the shop stores a normal https link to it - faster pages, and
  pictures stop counting against Firestore's 1 GiB free storage limit. Set up:
    1. In your Supabase project, go to Storage and create a bucket named exactly "strand-images". Set it Public
       (so shoppers' browsers can load the pictures directly).
    2. Project Settings > API > copy the Project URL into SUPABASE_URL and the service_role key into
       SUPABASE_SERVICE_KEY.
    3. Redeploy. No table or schema needed - this only uses Storage, not the Supabase database.

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
