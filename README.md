# Sveltia CMS OAuth Handler (PHP)

PHP implementation of the Sveltia CMS OAuth authenticator for GitHub and GitLab.

Based on: https://github.com/sveltia/sveltia-cms-auth

## When to Use This Handler

### Use this if:
- You have **multiple editors** who need GitHub authentication (not just you)
- Your users are **non-technical** and prefer a login button over personal access tokens
- You want a **seamless user experience** without managing PATs

### Alternatives:
- **GitHub PKCE (Recommended for single user)**: Sveltia CMS now supports client-side authentication directly with GitHub using PKCE. No backend needed! Just configure your GitHub OAuth app with PKCE enabled and use it directly in Sveltia CMS config.
- **Personal Access Token (Simplest for developers)**: If you're the only user, generate a [GitHub PAT](https://github.com/settings/tokens) and use it directly in Sveltia CMS config. Much simpler than setting up this authenticator.
- **GitLab OAuth**: Supported! Configure with GitLab OAuth application

## Setup Instructions

### 1. Deploying the solution

Before configuring OAuth, deploy the handler and update Sveltia CMS to use it.

- Install the handler into your project (see **Including the handler** above). A common location is `static/oauth`.
- Update Sveltia CMS backend configuration to point to the handler by setting `base_url` in `static/admin/config.yml`:

#### For GitHub:
```yaml
backend:
  name: github
  repo: your-username/your-repo
  branch: main
  base_url: https://your-site.com/oauth
```

#### For GitLab:
```yaml
backend:
  name: gitlab
  repo: your-username/your-repo
  branch: main
  base_url: https://your-site.com/oauth
```

- Test the setup:
  1. Visit your Sveltia CMS admin panel
  2. Click login with GitHub (or GitLab)
  3. You should be redirected to the provider's authorization page
  4. After authorizing, you should receive an access token and be logged in

### 2. Register OAuth App on GitHub or GitLab

#### For GitHub:

1. Go to https://github.com/settings/applications/new
2. Create a new OAuth Application with these settings:
   - **Application name**: Sveltia CMS Authenticator (or your preferred name)
   - **Homepage URL**: https://your-site.com (your site URL)
   - **Application description**: (optional)
   - **Authorization callback URL**: `https://your-site.com/oauth/callback`
   - **Enable Device Flow**: (optional)

3. After creation, you'll see:
   - **Client ID**: Copy this value
   - **Client Secret**: Click "Generate a new client secret" and copy it

#### For GitLab:

1. Go to https://gitlab.com/-/user_settings/applications (or your GitLab instance)
2. Create a new Application with these settings:
   - **Name**: Sveltia CMS Authenticator
   - **Redirect URI**: `https://your-site.com/oauth/callback`
   - **Scopes**: Select `api` (for repository access)

3. After creation, you'll see:
   - **Application ID**: Copy this value
   - **Secret**: Copy this value

### 3. Configure Environment Variables

The OAuth handler reads these environment variables. Set these in your PHP server environment (e.g., `.env`, Apache, or PHP-FPM):

#### For GitHub:
```bash
export GITHUB_CLIENT_ID="your-client-id"
export GITHUB_CLIENT_SECRET="your-client-secret"
```

#### For GitLab:
```bash
export GITLAB_CLIENT_ID="your-application-id"
export GITLAB_CLIENT_SECRET="your-secret"
export GITLAB_HOSTNAME="gitlab.com"  # optional, for self-hosted GitLab
```

#### Common (both):
```bash
export ALLOWED_DOMAINS="your-site.com,www.your-site.com"  # optional, comma-separated
export DEBUG_OAUTH="0"  # optional, set to 1 to enable debug logging
```

**For PHP Server:**
- Make sure these variables are set in your PHP server environment. Common locations:
  - `.env` file (if using php-dotenv)
  - Apache VirtualHost configuration
  - PHP-FPM pool configuration
  - System environment variables


## OAuth Flow
## OAuth Flow

The handler implements the standard OAuth authorization code flow for GitHub and GitLab:

1. **`GET /auth`** or **`GET /oauth/authorize`**
   - Initiates OAuth flow
   - Parameters:
     - `provider`: Must be `github` or `gitlab`
     - `site_id`: Your site domain (checked against ALLOWED_DOMAINS)
   - Redirects user to GitHub/GitLab authorization page

2. **`GET /callback`** or **`GET /oauth/redirect`**
   - GitHub/GitLab redirects here after user authorizes
   - Exchanges authorization code for access token
   - Returns HTML that posts token back to Sveltia CMS

## Security Features

- **CSRF Protection**: Uses CSRF tokens stored in HttpOnly cookies
- **Domain Validation**: Validates site domain against whitelist
- **Token Verification**: Validates state parameter matches stored token
- **Secure Cookies**: CSRF cookie uses `HttpOnly` and `SameSite=Lax` by default; use `SameSite=None; Secure` only when HTTPS is guaranteed for cross-site contexts
- **Token Expiration**: CSRF tokens expire after 10 minutes
- **Redacted Debug Logging**: If `DEBUG_OAUTH` is enabled, debug messages are written to `debug.log` but are automatically sanitized — common secrets (access_token, refresh_token, client_secret, client_id, codes and Authorization Bearer tokens) are redacted to avoid accidental leakage.

## Optional: Domain Whitelisting

The `ALLOWED_DOMAINS` variable supports wildcard patterns; the handler uses a strict, "fail-closed" policy by default (if `ALLOWED_DOMAINS` is empty, all domains are rejected).

Supported patterns:

```
# Single domain (exact match)
ALLOWED_DOMAINS="your-site.com"

# Multiple domains
ALLOWED_DOMAINS="your-site.com,www.your-site.com,docs.your-site.com"

# Wildcard (left-anchored only; matches subdomains but not the apex)
ALLOWED_DOMAINS="*.your-site.com,your-site.com"

# Complex pattern
ALLOWED_DOMAINS="*.example.com,another.com"
```

Notes:
- Only exact domains and leading wildcard patterns (`*.domain.tld`) are supported. Other wildcard forms are ignored to avoid accidental overbroad matching.
- Patterns and domains are normalized using IDNA (punycode) for consistent matching of internationalized domains.
- If `ALLOWED_DOMAINS` is not configured in production, the handler will reject requests by default to avoid accidental open access.

### SSRF Protections
- The handler validates that OAuth token URLs resolve to *public* IP addresses before performing token exchange requests.
- cURL is used for token exchange and the resolved public IPs are pinned using `CURLOPT_RESOLVE` to guard against DNS rebinding attacks.
- If no public IPs are found or cURL is unavailable, the token exchange is refused to reduce SSRF risk.

## Troubleshooting

### "Your domain is not allowed"
- Check ALLOWED_DOMAINS environment variable is set correctly
- Verify the domain in your Sveltia CMS config matches ALLOWED_DOMAINS

### "OAuth app client ID or secret is not configured"
- Verify GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET are set
- Check they're set in the PHP server's environment, not just shell

### "Failed to receive an authorization code"
- Ensure Authorization callback URL is set correctly in GitHub OAuth app settings
- Check that the callback URL matches your actual domain

### HTTPS Required
- OAuth over HTTP is not supported
- Ensure your site uses HTTPS
- Set secure cookies appropriately for your environment

### Debugging & Tests
- To enable debug logging: `export DEBUG_OAUTH="1"` (logs written to `static/oauth/debug.log`)
- Debug messages are sanitized automatically to redact secrets

## Including the handler (copy or submodule) ✅

You can include the handler from the upstream project <https://github.com/lenoxys/oauth-php-for-sveltia> in two common ways: copy the files into your repo (simple, one-time) or add it as a git submodule (tracks upstream changes).

- Copy the files (easy, edit freely):

```bash
# clone temporarily, copy the handler, then remove temp clone
git clone --depth 1 https://github.com/lenoxys/oauth-php-for-sveltia /tmp/oauth-temp
cp -R /tmp/oauth-temp/static/oauth ./static/oauth
rm -rf /tmp/oauth-temp
# commit into your repo
git add static/oauth
git commit -m "Add oauth handler (copied from upstream)"
```

- Add as a git submodule (recommended if you want upstream tracking):

```bash
# add as submodule at static/oauth
git submodule add https://github.com/lenoxys/oauth-php-for-sveltia static/oauth
git commit -m "Add oauth handler as submodule"

# clone with submodules
git clone --recurse-submodules <your-repo-url>
# or initialize submodules in an existing clone
git submodule update --init --recursive

# to update the submodule to latest upstream (example: main branch)
git submodule update --remote --merge --recursive
# or inside the submodule folder:
cd static/oauth && git checkout main && git pull origin main && cd -
# commit the updated submodule reference in the parent repo
git add static/oauth
git commit -m "Update oauth submodule"
```

Notes:

- Submodules are pinned to a commit; updating requires committing the new submodule SHA in the parent repo.
- If you plan to modify and push upstream changes, fork the upstream repo and use your fork URL for the submodule.
- To remove a submodule:

```bash
git submodule deinit -f static/oauth
git rm -f static/oauth
rm -rf .git/modules/static/oauth
git commit -m "Remove submodule static/oauth"
```

## File Structure

```
static/oauth/
├── index.php          # Main OAuth handler
├── .htaccess          # URL rewriting rules
└── README.md          # This file
```

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_CLIENT_ID` | No* | OAuth app Client ID from GitHub |
| `GITHUB_CLIENT_SECRET` | No* | OAuth app Client Secret from GitHub |
| `GITHUB_HOSTNAME` | No | Default: `github.com` (for GitHub Enterprise) |
| `GITLAB_CLIENT_ID` | No* | OAuth app Application ID from GitLab |
| `GITLAB_CLIENT_SECRET` | No* | OAuth app Secret from GitLab |
| `GITLAB_HOSTNAME` | No | Default: `gitlab.com` (for self-hosted GitLab) |
| `ALLOWED_DOMAINS` | No | Comma-separated list of allowed domains with wildcard support |
| `DEBUG_OAUTH` | No | Enable debug logging to `debug.log` |

*At least one provider (GitHub or GitLab) must be configured

## Future Enhancements

### PKCE Support (GitHub)
GitHub now supports client-side PKCE authentication for SPAs. For new projects, consider using [Sveltia CMS with PKCE](https://github.com/sveltia/sveltia-cms) instead of this backend authenticator.

## References

- [Sveltia CMS Documentation](https://github.com/sveltia/sveltia-cms)
- [Sveltia CMS Auth](https://github.com/sveltia/sveltia-cms-auth)
- [GitHub OAuth Apps Documentation](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps)
- [GitHub OAuth Authorization Flow](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)
- [GitLab OAuth Documentation](https://docs.gitlab.com/ee/api/oauth2.html)
- [GitLab OAuth Authorization Code Flow](https://docs.gitlab.com/ee/api/oauth2.html#authorization-code-flow)

## License

Same as Sveltia CMS (MIT)
