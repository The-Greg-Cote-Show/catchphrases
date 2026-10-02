# Greg Cote's Top 75 Catchphrase Countdown: Your Turn

Fan voting for The Greg Cote Show. Greg counted down his Top 75 catchphrases. Fans get three ways to weigh in:

1. **Your Top 10**: pick 10 of the 75.
2. **Your Number 1**: pick one.
3. **Redo the Countdown**: reorder all 75.

One vote per exercise per connection. Results stay private until the admin clicks "Go live".

## How it's built

- `index.html`, `results.html`, `catchphrases.json`: static pages on GitHub Pages. No build step.
- `worker.js` + `wrangler.toml`: one Cloudflare Worker (Workers Free). It checks votes, stores them in D1, and serves the admin dashboard.
- `schema.sql`: the D1 tables. Run it once in the D1 console.

The Worker does no number crunching. The admin dashboard pulls raw rows and does all the math in the browser.

## Setup

See [SETUP.md](SETUP.md). Everything is done in the browser.

## Secrets

`ADMIN_KEY`, `IP_SALT`, and `TURNSTILE_SECRET` live in Cloudflare secrets only. Never put them in this repo.

## Editing catchphrase text

Change the text in `catchphrases.json`. Votes store ids only (id = Greg's rank), so text edits never break stored votes or results. Don't change the ids.
