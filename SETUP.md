# SETUP (browser only)

One step at a time. Do them in order. Every step happens in a web browser.

> If the overnight deploy ran, some steps are already done for you. MORNING.md lists which ones. Those steps are marked **(maybe done overnight)** below.

You'll need: your GitHub login (The-Greg-Cote-Show), your Cloudflare login, and your Hover login.

---

## Step 1. Put the files on GitHub

1. Go to github.com and sign in.
2. Top right, click **+**, then **New repository**.
3. Repository name: `catchphrases` (any name works, but the rest of this guide assumes `catchphrases`).
4. Pick **Public**. (Free GitHub Pages needs a public repo. There are no secrets in these files.)
5. Click **Create repository**.
6. On the empty repo page, click the link **uploading an existing file**.
7. Drag in these 8 files from the Catchphrase Polls folder:
   `index.html`, `results.html`, `catchphrases.json`, `worker.js`, `wrangler.toml`, `schema.sql`, `README.md`, `SETUP.md`
8. Do NOT upload the `tools`, `tests`, `.wrangler`, or `.claude` folders, or any `.txt` files.
9. Click **Commit changes**.

## Step 2. Create the database **(maybe done overnight)**

1. Go to dash.cloudflare.com and sign in.
2. In the left sidebar, open **Storage & databases**, then **D1 SQL database**.
3. Click **Create Database**.
4. Name: `catchphrase-db`. Leave the location alone.
5. Click **Create**.
6. You land on the database page. Copy the **Database ID** (a long string of letters and numbers). Keep it handy for Step 4.

## Step 3. Create the tables **(maybe done overnight)**

1. Still on the `catchphrase-db` page, click the **Console** tab.
2. Open `schema.sql` (on GitHub or on your computer), copy all of it, and paste it into the console box.
3. Click **Execute**.
4. Check the **Tables** list. You should see `submissions`, `settings`, and `snapshots`.

It's safe to run again. It won't wipe anything.

## Step 4. Put the database ID in wrangler.toml **(maybe done overnight)**

1. On GitHub, open your `catchphrases` repo and click `wrangler.toml`.
2. Click the pencil icon (**Edit this file**).
3. Find `database_id = "REPLACE_WITH_D1_DATABASE_ID"` and swap in your Database ID, keeping the quotes.
4. Click **Commit changes**.

## Step 5. Connect GitHub to Cloudflare (Workers Builds)

This makes GitHub the source of truth. Every time you commit to `main`, Cloudflare redeploys the Worker. Never edit the Worker code in the Cloudflare dashboard.

**If the Worker `catchphrase-vote` already exists** (the overnight deploy made it):
1. Cloudflare dashboard, left sidebar: **Compute (Workers)**, then **Workers & Pages**.
2. Click `catchphrase-vote`.
3. Click **Settings**, then find **Builds**.
4. Click **Connect**. Pick GitHub, allow access to just the `catchphrases` repo, and pick branch `main`.
5. Leave the build command empty. Leave the deploy command as `npx wrangler deploy`.
6. Save.

**If it doesn't exist yet:**
1. **Workers & Pages**, then **Create application**.
2. Next to **Import a repository**, click **Get started**.
3. Connect your GitHub account and pick the `catchphrases` repo.
4. The project name must be exactly `catchphrase-vote` (it has to match `name` in wrangler.toml or the build fails).
5. Click **Save and Deploy**.

Either way, wait for the build to show a green check.

## Step 6. Make the Turnstile widget (stops bots)

1. Cloudflare dashboard, left sidebar: **Turnstile**.
2. Click **Add widget**.
3. Widget name: `Catchphrase vote`.
4. Hostnames: add `catchphrases.thegregcoteshow.com` and `the-greg-cote-show.github.io`.
5. Widget mode: **Managed**.
6. Click **Create**.
7. You'll see two keys:
   - **Site Key**: public. It goes in index.html (Step 8).
   - **Secret Key**: private. It goes in Cloudflare secrets (Step 7). Never put it on GitHub.

## Step 7. Set the three secrets **(ADMIN_KEY and IP_SALT maybe done overnight)**

1. **Workers & Pages**, click `catchphrase-vote`, then **Settings**.
2. Under **Variables and Secrets**, click **Add**.
3. Type: **Secret**. Variable name: `TURNSTILE_SECRET`. Value: the Turnstile **Secret Key** from Step 6.
4. Click **Deploy**.
5. If the overnight deploy did NOT set them, add these two the same way:
   - `ADMIN_KEY`: a long random password (30+ characters). This unlocks the admin dashboard. Save it in your password manager.
   - `IP_SALT`: another long random string. Set it once and never change it. Changing it resets the one-vote-per-connection memory.

Secrets stay put when GitHub redeploys the Worker.

## Step 8. Point the pages at the Worker and Turnstile

1. Find your Worker URL: **Workers & Pages**, click `catchphrase-vote`. It looks like `https://catchphrase-vote.SOMETHING.workers.dev`.
2. On GitHub, open `index.html`, click the pencil, and find these two lines near the bottom:
   ```
   const API_BASE = "https://REPLACE-WITH-WORKER-URL";
   const TURNSTILE_SITE_KEY = "REPLACE-WITH-TURNSTILE-SITE-KEY";
   ```
3. Put in your Worker URL (no slash at the end) and your Turnstile **Site Key**. Commit.
4. Open `results.html`, find `const API_BASE = ...`, put in the same Worker URL. Commit.

(If the overnight deploy ran, index.html and results.html on your computer already have the Worker URL. You can upload those two files instead of editing by hand. You still need to add the Site Key.)

## Step 9. Turn on GitHub Pages

1. In the repo, click **Settings**, then **Pages** (left side).
2. Under **Build and deployment**, Source: **Deploy from a branch**. Branch: `main`, folder `/ (root)`. Click **Save**.
3. In a minute or two the site is live at `https://the-greg-cote-show.github.io/catchphrases/`.
4. In **Custom domain**, type `catchphrases.thegregcoteshow.com` and click **Save**. (GitHub adds a CNAME file to the repo. That's expected.)

## Step 10. Add the CNAME at Hover

1. Go to hover.com and sign in.
2. Click `thegregcoteshow.com`, then the **DNS** tab.
3. Click **Add A Record** (Hover's button for any record type).
4. Type: **CNAME**. Hostname: `catchphrases`. Target: `the-greg-cote-show.github.io` (just that, no `/catchphrases` on the end).
5. Save.
6. DNS can take up to an hour. When GitHub Pages shows the domain as working, go back to repo **Settings > Pages** and tick **Enforce HTTPS**.

## Step 11. Check SITE_URL

`wrangler.toml` has `SITE_URL = "https://the-greg-cote-show.github.io/catchphrases"` for now. The admin dashboard and Preview load the catchphrase text and results.html from there. Once the custom domain works, change it to `https://catchphrases.thegregcoteshow.com` and commit. Keep the quotes that are already in the file; change only the text between them.

## Step 12. Open the admin dashboard

1. Go to `https://catchphrase-vote.SOMETHING.workers.dev/admin?key=YOUR_ADMIN_KEY`
2. At the top you should see **Voting: CLOSED** and **Results: PRIVATE**. Voting starts closed on purpose.
3. When you're ready for fans, click **Open voting**.

Don't share screenshots that show the address bar. The key is in the URL.

## Step 13. Test it live (from your phone)

1. Open `https://catchphrases.thegregcoteshow.com` on your phone and do the Top 10.
2. Reload the page in the same browser. The Top 10 card should say **Done**, and tapping it should say "Your Top 10 is already in." The server remembers your device. A different phone on the same Wi-Fi CAN vote. That's on purpose, so families and offices aren't blocked. One connection can send at most `MAX_PER_CONNECTION` votes per exercise (set in wrangler.toml, default 10).
3. Open `/admin` with no key, then with a wrong key. Both should say "Wrong or missing key."
4. Open `https://catchphrases.thegregcoteshow.com/results.html`. It should say "Results coming soon".
5. Open `https://catchphrase-vote.SOMETHING.workers.dev/api/results`. It should say `"public":false` and "Results coming soon", with no numbers.

## Before launch: clear your test votes

In the dashboard, click **Clear all votes**. When it asks, type `CLEAR` (capital letters, no quotes) and click OK. Every vote and every saved snapshot is removed, and results go back to private. Click **Download CSV** first if you want a copy.

## Results day

1. In the dashboard, scroll to **Biggest Omissions**. Work through **Possible matches** (Same thing / Different), fix group names, exclude junk, and click **Save review**.
2. Click **Save snapshot**.
3. Click **Preview public page** to see exactly what fans will see.
4. Happy with it? Click **Go live** and confirm.
5. Changed your mind? Click **Take offline**.
