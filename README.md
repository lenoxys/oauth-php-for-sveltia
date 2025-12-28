# Sveltia OAuth Handler (PHP)

Simple PHP OAuth handler for Sveltia CMS supporting GitHub and GitLab.

Based on: https://github.com/sveltia/sveltia-cms-auth

---

## Quick start

1. Install into your site at `static/oauth` (clone or submodule):

```bash
# clone
git clone https://github.com/lenoxys/oauth-php-for-sveltia static/oauth
# or as a submodule (recommended for upstream tracking)
git submodule add https://github.com/lenoxys/oauth-php-for-sveltia.git static/oauth
```

2. Set required environment variables (see summary below), including `ALLOWED_DOMAINS`.
3. Set `backend.base_url` in `static/admin/config.yml` to `https://your-site.com/oauth`.
4. Visit Sveltia admin, click "Login with GitHub" or "Login with GitLab" and complete the flow.

---

## Register OAuth App

- GitHub: create an OAuth App with callback `https://your-site.com/oauth/callback` and copy the Client ID/Secret.
- GitLab: create an Application with redirect URI `https://your-site.com/oauth/callback` and copy the ID/Secret.

---

## Environment variables (minimum)

- `ALLOWED_DOMAINS` **(required)** — comma-separated domains (supports leading `*.` patterns).
- `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` — for GitHub provider.
- `GITLAB_CLIENT_ID`, `GITLAB_CLIENT_SECRET`, `GITLAB_HOSTNAME` — for GitLab (hostname defaults to `gitlab.com`).
- `DEBUG_OAUTH=1` enables sanitized debug logging.

Set these in your PHP environment (.env, PHP-FPM, Apache, etc.).

---

## How it works (short)

- `GET /auth` (or `/oauth/authorize`) starts the OAuth flow with `provider=github|gitlab` and `site_id` (must be in `ALLOWED_DOMAINS`).
- Provider redirects to `GET /callback` (or `/oauth/redirect`), the handler exchanges the code for a token and posts the token back to Sveltia CMS.

---

## Security & restrictions

- Requires `ALLOWED_DOMAINS` (fail-closed by default).
- CSRF protection via HttpOnly cookies and state tokens.
- Token exchanges are protected against SSRF by validating resolved IPs and using pinned cURL resolves.
- Debug logs are sanitized to avoid exposing secrets.

---

## Troubleshooting

- "Domain not allowed": check `ALLOWED_DOMAINS` and `site_id` in your request.
- Missing client ID/secret: ensure they are available in the PHP process environment.
- Callback/code issues: verify OAuth app callback URL matches your site.
- HTTPS is required for secure cookies and production use.

---

## Install & Update

Install the handler into `static/oauth` (clone or submodule). Update commands:

- Clone: `cd static/oauth && git pull`
- Submodule: `git submodule update --remote --merge`
- To update to a specific release: fetch the tag or download the release archive and extract `static/oauth` only

Notes:
- If you modify the handler, prefer a fork or manage updates via releases to avoid overwriting local changes.

---

## File layout

```
static/oauth/
├─ index.php
├─ .htaccess
└─ README.md
```

---

## References & License

- Sveltia CMS: https://github.com/sveltia/sveltia-cms
- Sveltia CMS Auth: https://github.com/sveltia/sveltia-cms-auth
- GitHub/GitLab OAuth docs linked in the project

License: MIT (same as Sveltia CMS)
