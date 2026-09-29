<?php

/**
 * Sveltia CMS OAuth Handler for PHP
 *
 * Handles OAuth authentication for Sveltia CMS (GitHub, GitLab)
 * Based on: https://github.com/sveltia/sveltia-cms-auth
 * License: MIT
 * See README.md for usage details.
 */

function env($key, $default = '')
{
    return $_ENV[$key] ?? $_SERVER[$key] ?? $default;
}

function is_https()
{
    return !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
}

function providers()
{
    $callback = base_url() . '/callback';

    return [
        'github' => [
            'client_id' => env('GITHUB_CLIENT_ID'),
            'client_secret' => env('GITHUB_CLIENT_SECRET'),
            'hostname' => env('GITHUB_HOSTNAME', 'github.com'),
            'authorize_path' => '/login/oauth/authorize',
            'token_path' => '/login/oauth/access_token',
            'scope' => 'repo',
            'authorize_params' => [],
            'token_params' => [],
        ],
        'gitlab' => [
            'client_id' => env('GITLAB_CLIENT_ID'),
            'client_secret' => env('GITLAB_CLIENT_SECRET'),
            'hostname' => env('GITLAB_HOSTNAME', 'gitlab.com'),
            'authorize_path' => '/oauth/authorize',
            'token_path' => '/oauth/token',
            'scope' => 'api',
            'authorize_params' => ['redirect_uri' => $callback, 'response_type' => 'code'],
            'token_params' => ['grant_type' => 'authorization_code', 'redirect_uri' => $callback],
        ],
    ];
}

function debug_log($message)
{
    if (empty(env('DEBUG_OAUTH', false))) {
        return;
    }
    $message = sanitize_debug_message($message);
    @file_put_contents(__DIR__ . '/debug.log', '[' . date('Y-m-d H:i:s') . "] {$message}\n", FILE_APPEND);
    error_log($message);
}

/**
 * Sanitize debug messages by redacting common secrets and tokens.
 */
function sanitize_debug_message($message)
{
    if (!is_string($message)) {
        $message = json_encode($message, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    $redactions = [
        // JSON-like structures
        '/("?(?:access_token|refresh_token|token|client_secret|client_id|code|state)"?\s*[:=]\s*)"?[^",}\s]+"?/i' => '$1"[REDACTED]"',
        // URL parameters
        '/([?&](?:code|token|state|client_secret|client_id)=)[^&\s]+/i' => '$1[REDACTED]',
        // Authorization headers
        '/(Authorization:\s*(?:Bearer|Basic)\s+)[^\s,;]+/i' => '$1[REDACTED]',
        // CSRF cookies
        '/(csrf-token=)[A-Za-z0-9_\-]+/i' => '$1[REDACTED]',
        // GitHub/GitLab tokens (specific patterns)
        '/\b(ghp|gho|ghu|ghs|ghr|glpat)-[A-Za-z0-9_\-]+\b/i' => '[REDACTED_TOKEN]',
        // Long hex/alphanumeric strings
        '/\b[0-9a-f]{32,}\b/i' => '[REDACTED_HEX]',
        '/\b[A-Za-z0-9_\-]{40,}\b/' => '[REDACTED_LONG]',
    ];

    return preg_replace(array_keys($redactions), array_values($redactions), $message);
}

/**
 * Lowercase ASCII (punycode) form of a hostname, or false if it isn't a valid one.
 */
function ascii_hostname($name)
{
    if (function_exists('idn_to_ascii')) {
        $name = @idn_to_ascii($name, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
    }
    $name = strtolower((string) $name);

    return filter_var($name, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) ? $name : false;
}

/**
 * Match against a comma-separated list of exact domains or left-wildcard patterns like "*.example.com".
 * Fail-closed: an empty list rejects everything.
 */
function is_domain_allowed($domain, $allowed_domains)
{
    if (empty($allowed_domains)) {
        debug_log('ERROR: ALLOWED_DOMAINS not set - rejecting all domains by default.');
        return false;
    }

    $domain = is_string($domain) && $domain !== '' ? ascii_hostname($domain) : false;
    if (!$domain) {
        debug_log('Invalid domain');
        return false;
    }

    foreach (explode(',', $allowed_domains) as $pattern) {
        $pattern = trim($pattern);
        $wildcard = str_starts_with($pattern, '*.');
        $base = $pattern === '' ? false : ascii_hostname($wildcard ? substr($pattern, 2) : $pattern);
        if (!$base) {
            continue;
        }
        if ($domain === $base || ($wildcard && str_ends_with($domain, '.' . $base))) {
            return true;
        }
    }

    debug_log('Domain not allowed: ' . $domain);
    return false;
}

function set_csrf_cookie($value, $max_age)
{
    $flags = 'HttpOnly; SameSite=Lax; Path=/oauth/; Max-Age=' . intval($max_age);
    if (is_https()) {
        $flags = 'Secure; ' . $flags;
    }
    if (!empty($_SERVER['HTTP_HOST'])) {
        $flags .= '; Domain=' . $_SERVER['HTTP_HOST'];
    }
    header("Set-Cookie: csrf-token={$value}; {$flags}", false);
}

/**
 * Post the result back to Sveltia CMS. $payload is either ['token' => ...] or ['error' => ..., 'errorCode' => ...].
 */
function output_html($provider, $payload)
{
    $nonce = bin2hex(random_bytes(16));
    $state = isset($payload['error']) ? 'error' : 'success';
    $content = json_encode(['provider' => $provider] + $payload);

    set_csrf_cookie('deleted', 0);
    header('Content-Type: text/html; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: no-referrer');
    if (is_https()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
    header("Content-Security-Policy: default-src 'none'; script-src 'nonce-{$nonce}'; connect-src 'self'");

    if ($state === 'error') {
        http_response_code(400);
    }

    echo <<<HTML
<!doctype html>
<html>
<body>
<script nonce="{$nonce}">
(() => {
  window.addEventListener('message', ({ data, origin }) => {
    if (data === 'authorizing:$provider') {
      if (origin === window.location.origin) {
        window.opener?.postMessage(
          'authorization:$provider:$state:$content',
          origin
        );
      }
    }
  });
  window.opener?.postMessage('authorizing:$provider', window.location.origin);
})();
</script>
</body>
</html>
HTML;
}

function handle_auth()
{
    $providers = providers();
    $name = $_GET['provider'] ?? null;
    $provider = is_string($name) && !empty($providers[$name]['client_id']) ? $providers[$name] : null;

    if (!$provider) {
        return output_html('unknown', ['error' => 'Your Git backend is not supported by the authenticator.', 'errorCode' => 'UNSUPPORTED_BACKEND']);
    }
    if (!is_domain_allowed($_GET['site_id'] ?? null, env('ALLOWED_DOMAINS'))) {
        return output_html($name, ['error' => 'Your domain is not allowed to use the authenticator.', 'errorCode' => 'UNSUPPORTED_DOMAIN']);
    }
    if (empty($provider['client_secret'])) {
        return output_html($name, ['error' => 'OAuth app client ID or secret is not configured.', 'errorCode' => 'MISCONFIGURED_CLIENT']);
    }

    $csrf_token = bin2hex(random_bytes(32));
    set_csrf_cookie("{$name}_{$csrf_token}", 600);
    header('Location: https://' . $provider['hostname'] . $provider['authorize_path'] . '?' . http_build_query([
        'client_id' => $provider['client_id'],
        'scope' => $provider['scope'],
        'state' => $csrf_token,
    ] + $provider['authorize_params']));
    exit;
}

function handle_callback()
{
    $code = $_GET['code'] ?? null;
    $state = $_GET['state'] ?? null;
    $csrf_cookie = $_COOKIE['csrf-token'] ?? '';

    debug_log('Callback - code: ' . ($code ? 'received' : 'missing') . ', state: ' . ($state ? 'received' : 'missing'));

    if (!is_string($csrf_cookie) || !preg_match('/^(github|gitlab)_([0-9a-f]{64})$/', $csrf_cookie, $matches)) {
        debug_log('Callback - missing or invalid CSRF cookie: ' . json_encode($csrf_cookie));
        return output_html('unknown', ['error' => 'Potential CSRF attack detected. Authentication flow aborted.', 'errorCode' => 'CSRF_DETECTED']);
    }

    list(, $name, $csrf_token) = $matches;
    $provider = providers()[$name];

    if (empty($provider['client_id'])) {
        return output_html('unknown', ['error' => 'Unknown provider.', 'errorCode' => 'INVALID_PROVIDER']);
    }
    if (!$code || !$state) {
        return output_html($name, ['error' => 'Failed to receive an authorization code. Please try again later.', 'errorCode' => 'AUTH_CODE_REQUEST_FAILED']);
    }
    if (!is_string($state) || !hash_equals($csrf_token, $state)) {
        debug_log("Callback - CSRF mismatch! State: $state, Token: $csrf_token");
        return output_html($name, ['error' => 'Potential CSRF attack detected. Authentication flow aborted.', 'errorCode' => 'CSRF_DETECTED']);
    }

    $response = fetch_token('https://' . $provider['hostname'] . $provider['token_path'], [
        'code' => $code,
        'client_id' => $provider['client_id'],
        'client_secret' => $provider['client_secret'],
    ] + $provider['token_params']);

    if ($response === false) {
        return output_html($name, ['error' => 'Failed to request an access token. Please try again later.', 'errorCode' => 'TOKEN_REQUEST_FAILED']);
    }

    $data = json_decode($response, true);
    if (!$data) {
        debug_log('Callback - JSON decode failed. Response: ' . $response);
        return output_html($name, ['error' => 'Server responded with malformed data. Please try again later.', 'errorCode' => 'MALFORMED_RESPONSE']);
    }

    $token = $data['access_token'] ?? '';
    $error = $data['error'] ?? '';
    $scope = $data['scope'] ?? '';

    if ($token && $scope && !str_contains($scope, $provider['scope'])) {
        debug_log('Callback - Scope validation failed. Got: ' . $scope);
        return output_html($name, ['error' => 'Insufficient permissions granted. Please ensure you grant repository access.', 'errorCode' => 'INSUFFICIENT_SCOPE']);
    }
    if ($error || !$token) {
        debug_log('Callback - Token error: ' . $error);
        return output_html($name, ['error' => $error ?: 'Failed to obtain access token.', 'errorCode' => 'TOKEN_REQUEST_FAILED']);
    }

    return output_html($name, ['token' => $token]);
}

function is_public_ip($ip)
{
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
}

/**
 * Resolve a hostname to its public IPv4/IPv6 addresses (private/reserved ranges filtered out).
 */
function resolve_public_ips($host)
{
    $ips = [];
    foreach (array_merge(@dns_get_record($host, DNS_A) ?: [], @dns_get_record($host, DNS_AAAA) ?: []) as $record) {
        $ips[] = $record['ipv6'] ?? $record['ip'] ?? null;
    }
    $ips = array_filter($ips, 'is_public_ip');

    if (!$ips) {
        $ips = array_filter(@gethostbynamel($host) ?: [], 'is_public_ip');
    }

    return array_values(array_unique($ips));
}

function fetch_token($url, $body)
{
    debug_log('Fetching token from: ' . $url);
    debug_log(['event' => 'FetchTokenRequest', 'body' => $body]);

    $host = parse_url($url, PHP_URL_HOST);
    $ips = resolve_public_ips($host);
    if (!$ips) {
        debug_log('No public IPs found for host: ' . $host);
        return false;
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($body),
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'Content-Type: application/json',
            'User-Agent: Sveltia-CMS-Auth-PHP',
        ],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT => 15,
        // HTTPS only, verified, and pinned to the resolved public IPs to mitigate SSRF/DNS rebinding
        CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_RESOLVE => array_map(function ($ip) use ($host) {
            return "{$host}:443:{$ip}";
        }, $ips),
    ]);

    $response = curl_exec($ch);
    debug_log('cURL - HTTP code: ' . curl_getinfo($ch, CURLINFO_HTTP_CODE) . ', errno: ' . curl_errno($ch) . ', response: ' . ($response ?: 'false'));

    return $response;
}

function base_url()
{
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'];
    $base_path = str_replace('/index.php', '', dirname(filter_var($_SERVER['REQUEST_URI'] ?? '/', FILTER_SANITIZE_URL)));

    return (is_https() ? 'https' : 'http') . '://' . $host . rtrim($base_path, '/');
}

/**
 * Route path relative to /oauth/, e.g. "/oauth/index.php/callback/?x=1" -> "/callback".
 */
function request_path($uri)
{
    $path = preg_replace('#^(/oauth(?=/))?(/index\.php)?#', '', (string) parse_url($uri, PHP_URL_PATH));

    return '/' . trim($path, '/');
}

function route()
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'NONE';
    if ($method !== 'GET') {
        http_response_code(405);
        header('Allow: GET');
        debug_log('Invalid request method: ' . $method);
        return;
    }

    $path = request_path($_SERVER['REQUEST_URI'] ?? '/');
    debug_log('REQUEST_URI: ' . ($_SERVER['REQUEST_URI'] ?? 'N/A') . ', path: ' . $path . ', GET: ' . json_encode($_GET));

    if (in_array($path, ['/auth', '/authorize'], true)) {
        return handle_auth();
    }
    if (in_array($path, ['/callback', '/redirect'], true)) {
        return handle_callback();
    }

    debug_log('No route matched: ' . $path);
    http_response_code(404);
}

if (PHP_SAPI !== 'cli') {
    route();
}
