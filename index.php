<?php

/**
 * Sveltia CMS OAuth Handler for PHP
 * 
 * Handles OAuth authentication for Sveltia CMS (GitHub, GitLab, extensible for more providers)
 * Based on: https://github.com/sveltia/sveltia-cms-auth
 * 
 * Environment variables required:
 * - GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET (for GitHub)
 * - GITLAB_CLIENT_ID and GITLAB_CLIENT_SECRET (for GitLab)
 * - ALLOWED_DOMAINS (optional, comma-separated)
 */

// ============================================================================
// OAUTH PROVIDER INTERFACE & IMPLEMENTATIONS
// ============================================================================

/**
 * Abstract OAuth Provider
 */
abstract class SveltiaCMSOAuthProvider
{
    protected $debug_callback;

    public function setDebugCallback($callback)
    {
        $this->debug_callback = $callback;
    }

    protected function debugLog($message)
    {
        if (is_callable($this->debug_callback)) {
            call_user_func($this->debug_callback, $message);
        }
    }

    abstract public function getProviderName();
    abstract public function isConfigured();
    abstract public function getAuthorizationUrl($csrf_token, $base_url = null);
    abstract public function getCsrfCookieName();
    abstract public function getTokenExchangeData($code, $base_url = null);

    public function validateScope($scope)
    {
        return true;
    }

    public function extractToken($response_data)
    {
        return $response_data['access_token'] ?? '';
    }

    protected function validateHostname($hostname)
    {
        // Only allow valid hostnames, no IPs
        if (!filter_var($hostname, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            return false;
        }
        // Prevent localhost/private IPs
        $ip = gethostbyname($hostname);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return true;
        }
        return false;
    }
}

/**
 * GitHub OAuth Provider
 */
class GitHubProvider extends SveltiaCMSOAuthProvider
{
    private $client_id;
    private $client_secret;
    private $hostname;

    public function __construct($client_id = '', $client_secret = '', $hostname = 'github.com')
    {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->hostname = $hostname;

        if (!$this->validateHostname($hostname)) {
            throw new InvalidArgumentException('Invalid GitHub hostname');
        }
    }

    public function getProviderName()
    {
        return 'github';
    }

    public function isConfigured()
    {
        return !empty($this->client_id) && !empty($this->client_secret);
    }

    public function getAuthorizationUrl($csrf_token, $base_url = null)
    {
        $auth_params = [
            'client_id' => $this->client_id,
            'scope' => 'repo',
            'state' => $csrf_token
        ];
        return 'https://' . $this->hostname . '/login/oauth/authorize?' . http_build_query($auth_params);
    }

    public function getCsrfCookieName()
    {
        return 'github_';
    }

    public function getTokenExchangeData($code, $base_url = null)
    {
        return [
            'url' => 'https://' . $this->hostname . '/login/oauth/access_token',
            'body' => [
                'code' => $code,
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret
            ]
        ];
    }

    public function validateScope($scope)
    {
        return empty($scope) || strpos($scope, 'repo') !== false;
    }
}

/**
 * GitLab OAuth Provider
 */
class GitLabProvider extends SveltiaCMSOAuthProvider
{
    private $client_id;
    private $client_secret;
    private $hostname;

    public function __construct($client_id = '', $client_secret = '', $hostname = 'gitlab.com')
    {
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->hostname = $hostname;

        if (!$this->validateHostname($hostname)) {
            throw new InvalidArgumentException('Invalid GitLab hostname');
        }
    }

    public function getProviderName()
    {
        return 'gitlab';
    }

    public function isConfigured()
    {
        return !empty($this->client_id) && !empty($this->client_secret);
    }

    public function getAuthorizationUrl($csrf_token, $base_url = null)
    {
        $auth_params = [
            'client_id' => $this->client_id,
            'redirect_uri' => $base_url . '/callback',
            'response_type' => 'code',
            'scope' => 'api',
            'state' => $csrf_token
        ];
        return 'https://' . $this->hostname . '/oauth/authorize?' . http_build_query($auth_params);
    }

    public function getCsrfCookieName()
    {
        return 'gitlab_';
    }

    public function getTokenExchangeData($code, $base_url = null)
    {
        return [
            'url' => 'https://' . $this->hostname . '/oauth/token',
            'body' => [
                'code' => $code,
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret,
                'grant_type' => 'authorization_code',
                'redirect_uri' => $base_url . '/callback'
            ]
        ];
    }

    public function validateScope($scope)
    {
        return empty($scope) || strpos($scope, 'api') !== false;
    }
}

/**
 * OAuth Provider Factory
 */
class SveltiaCMSOAuthProviderFactory
{
    private $providers = [];

    public function __construct($config = [])
    {
        if (!empty($config['github_client_id'])) {
            $this->providers['github'] = new GitHubProvider(
                $config['github_client_id'],
                $config['github_client_secret'],
                $config['github_hostname'] ?? 'github.com'
            );
        }

        if (!empty($config['gitlab_client_id'])) {
            $this->providers['gitlab'] = new GitLabProvider(
                $config['gitlab_client_id'],
                $config['gitlab_client_secret'],
                $config['gitlab_hostname'] ?? 'gitlab.com'
            );
        }
    }

    public function getProvider($name)
    {
        return $this->providers[$name] ?? null;
    }

    public function hasProvider($name)
    {
        return isset($this->providers[$name]);
    }

    public function setDebugCallback($callback)
    {
        foreach ($this->providers as $provider) {
            $provider->setDebugCallback($callback);
        }
    }
}

// ============================================================================
// MAIN HANDLER
// ============================================================================

class SveltiaCMSAuthHandler
{
    private $provider_factory;
    private $allowed_domains;
    private $debug_log_file;
    private $debug_enabled;

    public function __construct()
    {
        $this->provider_factory = new SveltiaCMSOAuthProviderFactory([
            'github_client_id' => $_ENV['GITHUB_CLIENT_ID'] ?? $_SERVER['GITHUB_CLIENT_ID'] ?? '',
            'github_client_secret' => $_ENV['GITHUB_CLIENT_SECRET'] ?? $_SERVER['GITHUB_CLIENT_SECRET'] ?? '',
            'github_hostname' => $_ENV['GITHUB_HOSTNAME'] ?? $_SERVER['GITHUB_HOSTNAME'] ?? 'github.com',
            'gitlab_client_id' => $_ENV['GITLAB_CLIENT_ID'] ?? $_SERVER['GITLAB_CLIENT_ID'] ?? '',
            'gitlab_client_secret' => $_ENV['GITLAB_CLIENT_SECRET'] ?? $_SERVER['GITLAB_CLIENT_SECRET'] ?? '',
            'gitlab_hostname' => $_ENV['GITLAB_HOSTNAME'] ?? $_SERVER['GITLAB_HOSTNAME'] ?? 'gitlab.com',
        ]);

        $this->allowed_domains = $_ENV['ALLOWED_DOMAINS'] ?? $_SERVER['ALLOWED_DOMAINS'] ?? '';
        $this->debug_enabled = !empty($_ENV['DEBUG_OAUTH'] ?? $_SERVER['DEBUG_OAUTH'] ?? false);
        $this->debug_log_file = __DIR__ . '/debug.log';

        if ($this->debug_enabled) {
            $this->provider_factory->setDebugCallback([$this, 'debugLog']);
        }
    }

    public function debugLog($message)
    {
        if (!$this->debug_enabled) {
            return;
        }
        $msg = $this->sanitizeDebugMessage($message);
        $timestamp = date('Y-m-d H:i:s');
        $log_message = "[{$timestamp}] {$msg}\n";
        @file_put_contents($this->debug_log_file, $log_message, FILE_APPEND);
        error_log($msg);
    }

    /**
     * Sanitize debug messages by redacting common secrets and tokens.
     * Accepts strings, arrays and objects.
     */
    private function sanitizeDebugMessage($message)
    {
        if (is_array($message) || is_object($message)) {
            $message = json_encode($message, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }
        if (!is_string($message)) {
            $message = strval($message);
        }

        $patterns = [
            // JSON-like structures
            '/("?(?:access_token|refresh_token|token|client_secret|client_id|code|state)"?\s*[:=]\s*)"?[^",}\s]+"?/i',
            // URL parameters
            '/([?&](?:code|token|state|client_secret|client_id)=)[^&\s]+/i',
            // Authorization headers
            '/(Authorization:\s*(?:Bearer|Basic)\s+)[^\s,;]+/i',
            // CSRF cookies
            '/(csrf-token=)[A-Za-z0-9_\-]+/i',
            // GitHub/GitLab tokens (specific patterns)
            '/\b(ghp|gho|ghu|ghs|ghr|glpat)-[A-Za-z0-9_\-]+\b/i',
        ];
        $replacements = [
            '$1"[REDACTED]"',
            '$1[REDACTED]',
            '$1[REDACTED]',
            '$1[REDACTED]',
            '[REDACTED_TOKEN]',
        ];

        $message = preg_replace($patterns, $replacements, $message);
        // Mask long hex/alphanumeric strings
        $message = preg_replace('/\b[0-9a-f]{32,}\b/i', '[REDACTED_HEX]', $message);
        $message = preg_replace('/\b[A-Za-z0-9_\-]{40,}\b/', '[REDACTED_LONG]', $message);

        return $message;
    }

    private function escapeRegExp($str)
    {
        return preg_quote($str, '/');
    }

    private function isDomainAllowed($domain)
    {
        // Fail-closed: if no allowed domains configured, reject by default
        if (empty($this->allowed_domains)) {
            $this->debugLog("ERROR: ALLOWED_DOMAINS not set - rejecting all domains by default.");
            return false;
        }

        if (!is_string($domain) || $domain === '') {
            return false;
        }

        // Normalize to ASCII (punycode) for accurate comparison
        if (function_exists('idn_to_ascii')) {
            $domain_ascii = @idn_to_ascii($domain, IDNA_DEFAULT, defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : IDNA_DEFAULT);
            if ($domain_ascii === false) {
                $this->debugLog("Invalid domain (IDNA conversion failed): " . $domain);
                return false;
            }
        } else {
            $domain_ascii = $domain;
        }

        if (!filter_var($domain_ascii, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
            $this->debugLog("Invalid domain (not hostname): " . $domain_ascii);
            return false;
        }

        $allowed_list = array_map('trim', explode(',', $this->allowed_domains));
        foreach ($allowed_list as $pattern) {
            if ($pattern === '') {
                continue;
            }

            // Only support exact matches or left-wildcard patterns like "*.example.com"
            if (strpos($pattern, '*') !== false && strpos($pattern, '*.') !== 0) {
                $this->debugLog("Skipping unsupported domain pattern: " . $pattern);
                continue;
            }

            // Normalize pattern
            if (function_exists('idn_to_ascii')) {
                $pattern_ascii = @idn_to_ascii($pattern, IDNA_DEFAULT, defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : IDNA_DEFAULT);
                if ($pattern_ascii === false) {
                    $this->debugLog("Skipping invalid pattern (IDNA conversion failed): " . $pattern);
                    continue;
                }
            } else {
                $pattern_ascii = $pattern;
            }

            if (strpos($pattern_ascii, '*.') === 0) {
                $rest = substr($pattern_ascii, 2);
                if (!filter_var($rest, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
                    $this->debugLog("Skipping invalid wildcard base domain: " . $rest);
                    continue;
                }
                $rest_quoted = preg_quote($rest, '/');
                $regex = "/^([A-Za-z0-9-]+\\.)*{$rest_quoted}$/i";
            } else {
                $quoted = preg_quote($pattern_ascii, '/');
                $regex = "/^{$quoted}$/i";
            }

            if (preg_match($regex, $domain_ascii)) {
                return true;
            }
        }

        $this->debugLog("Domain not allowed: " . $domain_ascii);
        return false;
    }

    private function generateCsrfToken()
    {
        return bin2hex(random_bytes(32));
    }

    private function setCsrfCookie($value, $maxAge = 600)
    {
        $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        $sameSite = 'Lax';
        $domain = $_SERVER['HTTP_HOST'] ?? '';
        $path = '/oauth/';
        $flags = 'HttpOnly; SameSite=' . $sameSite . '; Path=' . $path . '; Max-Age=' . intval($maxAge);
        if ($secure) {
            $flags = 'Secure; ' . $flags;
        }
        if ($domain) {
            $flags .= '; Domain=' . $domain;
        }
        header("Set-Cookie: csrf-token={$value}; {$flags}", false);
    }

    private function outputHTML($args = [])
    {
        $provider = $args['provider'] ?? 'unknown';
        $token = $args['token'] ?? null;
        $error = $args['error'] ?? null;
        $errorCode = $args['errorCode'] ?? null;
        $nonce = bin2hex(random_bytes(16));

        $state = $error ? 'error' : 'success';
        $content = $error
            ? json_encode(['provider' => $provider, 'error' => $error, 'errorCode' => $errorCode])
            : json_encode(['provider' => $provider, 'token' => $token]);

        $this->setCsrfCookie('deleted', 0);
        header('Content-Type: text/html; charset=UTF-8');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: SAMEORIGIN');
        header('Referrer-Policy: no-referrer');
        if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
        }
        header("Content-Security-Policy: default-src 'none'; script-src 'nonce-{$nonce}'; connect-src 'self'");

        if ($error) {
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

    private function handleAuth()
    {
        $provider_name = $_GET['provider'] ?? null;
        $site_id = $_GET['site_id'] ?? null;

        // Basic input validation
        if ($provider_name && !preg_match('/^[a-z0-9_-]+$/i', $provider_name)) {
            return $this->outputHTML(['error' => 'Invalid provider', 'errorCode' => 'INVALID_PROVIDER']);
        }
        if ($site_id && !preg_match('/^[a-zA-Z0-9\-\.]+$/', $site_id)) {
            return $this->outputHTML(['provider' => $provider_name, 'error' => 'Invalid site_id', 'errorCode' => 'INVALID_SITE']);
        }

        $provider = $this->provider_factory->getProvider($provider_name);

        if (!$provider) {
            return $this->outputHTML([
                'error' => 'Your Git backend is not supported by the authenticator.',
                'errorCode' => 'UNSUPPORTED_BACKEND'
            ]);
        }

        if (!$this->isDomainAllowed($site_id)) {
            return $this->outputHTML([
                'provider' => $provider_name,
                'error' => 'Your domain is not allowed to use the authenticator.',
                'errorCode' => 'UNSUPPORTED_DOMAIN'
            ]);
        }

        if (!$provider->isConfigured()) {
            return $this->outputHTML([
                'provider' => $provider_name,
                'error' => 'OAuth app client ID or secret is not configured.',
                'errorCode' => 'MISCONFIGURED_CLIENT'
            ]);
        }

        $csrf_token = $this->generateCsrfToken();
        $auth_url = $provider->getAuthorizationUrl($csrf_token, $this->getBaseUrl());
        $cookie_name = $provider->getCsrfCookieName();

        $this->setCsrfCookie($cookie_name . $csrf_token, 600);
        header('Location: ' . $auth_url);
        exit;
    }

    private function handleCallback()
    {
        $code = $_GET['code'] ?? null;
        $state = $_GET['state'] ?? null;

        $this->debugLog("OAuth Debug Callback - Code: " . ($code ? 'received' : 'missing'));
        $this->debugLog("OAuth Debug Callback - State: " . ($state ? 'received' : 'missing'));

        $csrf_cookie = $_COOKIE['csrf-token'] ?? null;

        if (!$csrf_cookie) {
            return $this->outputHTML([
                'error' => 'Potential CSRF attack detected. Authentication flow aborted.',
                'errorCode' => 'CSRF_DETECTED'
            ]);
        }

        if (!preg_match('/^(github|gitlab)_([0-9a-f]{64})$/', $csrf_cookie, $matches)) {
            $this->debugLog("OAuth Debug Callback - Invalid CSRF cookie format: " . $csrf_cookie);
            return $this->outputHTML([
                'error' => 'Potential CSRF attack detected. Authentication flow aborted.',
                'errorCode' => 'CSRF_DETECTED'
            ]);
        }

        $provider_name = $matches[1];
        $csrf_token = $matches[2];

        $provider = $this->provider_factory->getProvider($provider_name);
        if (!$provider) {
            return $this->outputHTML([
                'error' => 'Unknown provider.',
                'errorCode' => 'INVALID_PROVIDER'
            ]);
        }

        if (!$code || !$state) {
            return $this->outputHTML([
                'provider' => $provider_name,
                'error' => 'Failed to receive an authorization code. Please try again later.',
                'errorCode' => 'AUTH_CODE_REQUEST_FAILED'
            ]);
        }

        if (!is_string($state) || !hash_equals($csrf_token, $state)) {
            $this->debugLog("OAuth Debug Callback - CSRF mismatch! State: $state, Token: $csrf_token");
            return $this->outputHTML([
                'provider' => $provider_name,
                'error' => 'Potential CSRF attack detected. Authentication flow aborted.',
                'errorCode' => 'CSRF_DETECTED'
            ]);
        }

        $exchange_data = $provider->getTokenExchangeData($code, $this->getBaseUrl());
        $response = $this->fetchToken($exchange_data['url'], $exchange_data['body']);

        if ($response === false) {
            $this->debugLog("OAuth Debug Callback - fetchToken returned false");
            return $this->outputHTML([
                'provider' => $provider_name,
                'error' => 'Failed to request an access token. Please try again later.',
                'errorCode' => 'TOKEN_REQUEST_FAILED'
            ]);
        }

        $data = @json_decode($response, true);

        if (!$data) {
            $this->debugLog("OAuth Debug Callback - JSON decode failed. Response: " . $response);
            return $this->outputHTML([
                'provider' => $provider_name,
                'error' => 'Server responded with malformed data. Please try again later.',
                'errorCode' => 'MALFORMED_RESPONSE'
            ]);
        }

        $token = $provider->extractToken($data);
        $error = $data['error'] ?? '';
        $scope = $data['scope'] ?? '';

        if ($token && $scope && !$provider->validateScope($scope)) {
            $this->debugLog("OAuth Debug Callback - Scope validation failed. Got: " . $scope);
            return $this->outputHTML([
                'provider' => $provider_name,
                'error' => 'Insufficient permissions granted. Please ensure you grant repository access.',
                'errorCode' => 'INSUFFICIENT_SCOPE'
            ]);
        }

        $this->setCsrfCookie('deleted', 0);

        if ($error || !$token) {
            $this->debugLog("OAuth Debug Callback - Token error: " . $error);
            return $this->outputHTML([
                'provider' => $provider_name,
                'error' => $error ?: 'Failed to obtain access token.',
                'errorCode' => 'TOKEN_REQUEST_FAILED'
            ]);
        }

        return $this->outputHTML([
            'provider' => $provider_name,
            'token' => $token
        ]);
    }

    private function fetchToken($token_url, $request_body)
    {
        $this->debugLog("OAuth Debug - Fetching token from: " . $token_url);
        $this->debugLog(['event' => 'FetchTokenRequest', 'body' => $request_body]);

        // Prefer cURL path which supports IP pinning to mitigate SSRF/DNS rebinding
        if (function_exists('curl_init')) {
            return $this->fetchTokenWithCurl($token_url, $request_body);
        }

        // Fallback to stream context only if host resolves to public IPs
        $u = parse_url($token_url);
        $host = $u['host'] ?? null;
        if ($host) {
            $ips = $this->resolvePublicIps($host);
            if (empty($ips)) {
                $this->debugLog("No public IP addresses found for token host: " . $host);
                return false;
            }
        }

        $json_body = json_encode($request_body);

        $context_options = [
            'http' => [
                'method' => 'POST',
                'header' => [
                    'Accept: application/json',
                    'Content-Type: application/json',
                    'User-Agent: Sveltia-CMS-Auth-PHP'
                ],
                'content' => $json_body,
                'timeout' => 10,
                'ignore_errors' => true
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'allow_self_signed' => false
            ]
        ];

        $context = stream_context_create($context_options);
        $response = @file_get_contents($token_url, false, $context);

        if ($response !== false) {
            $this->debugLog("OAuth Debug - Token response: " . $response);
        }

        return $response;
    }

    /**
     * Resolve public IP addresses for a hostname using DNS A/AAAA records and filter private/reserved ranges.
     * Returns array of IP strings (IPv4/IPv6) or empty array if none found.
     */
    private function resolvePublicIps($host)
    {
        $ips = [];
        // Use dns_get_record to get A and AAAA records
        $a_records = @dns_get_record($host, DNS_A) ?: [];
        $aaaa_records = @dns_get_record($host, DNS_AAAA) ?: [];

        foreach ($a_records as $r) {
            if (!empty($r['ip']) && $this->isIpPublic($r['ip'])) {
                $ips[] = $r['ip'];
            }
        }
        foreach ($aaaa_records as $r) {
            $ip = $r['ipv6'] ?? ($r['ip'] ?? null);
            if ($ip && $this->isIpPublic($ip)) {
                $ips[] = $ip;
            }
        }

        // As a fallback, try gethostbynamel (may return multiple IPs)
        if (empty($ips)) {
            $host_ips = @gethostbynamel($host) ?: [];
            foreach ($host_ips as $ip) {
                if ($this->isIpPublic($ip)) {
                    $ips[] = $ip;
                }
            }
        }

        return array_values(array_unique($ips));
    }

    private function isIpPublic($ip)
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }
        return true;
    }

    private function fetchTokenWithCurl($token_url, $request_body)
    {
        $ch = curl_init();

        // Resolve host and ensure we have public IP(s)
        $parts = parse_url($token_url);
        $host = $parts['host'] ?? null;
        $port = $parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80);
        if (!$host) {
            $this->debugLog("Invalid token URL, missing host: " . $token_url);
            return false;
        }

        $ips = $this->resolvePublicIps($host);
        if (empty($ips)) {
            $this->debugLog("No public IPs found for host: " . $host);
            return false;
        }

        // Build CURLOPT_RESOLVE entries to pin hostname to specific IPs
        $resolve = [];
        foreach ($ips as $ip) {
            $resolve[] = sprintf("%s:%d:%s", $host, $port, $ip);
        }

        curl_setopt($ch, CURLOPT_URL, $token_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($request_body));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: application/json',
            'Content-Type: application/json',
            'User-Agent: Sveltia-CMS-Auth-PHP'
        ]);
        // Connection and total timeouts
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15);

        // Enforce TLS/HTTPS only and verify host
        if (defined('CURLPROTO_HTTPS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        }
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

        // Pin the host to resolved public IPs to mitigate DNS rebinding
        curl_setopt($ch, CURLOPT_RESOLVE, $resolve);

        $response = curl_exec($ch);
        $curl_errno = curl_errno($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        $this->debugLog("OAuth Debug cURL - Response: " . ($response ? 'received' : 'false'));
        if ($response) {
            $this->debugLog("OAuth Debug cURL - Response: " . $response);
        }
        $this->debugLog("OAuth Debug cURL - HTTP code: " . $http_code);
        $this->debugLog("OAuth Debug cURL - Error number: " . $curl_errno);

        return $response;
    }

    private function getBaseUrl()
    {
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'];
        $base_path = dirname(filter_var($_SERVER['REQUEST_URI'] ?? '/', FILTER_SANITIZE_URL));

        $base_path = str_replace('/index.php', '', $base_path);
        if (substr($base_path, -1) === '/') {
            $base_path = rtrim($base_path, '/');
        }

        return $protocol . '://' . $host . $base_path;
    }

    private function getRequestPath()
    {
        if (!empty($_SERVER['REQUEST_URI'])) {
            $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
        } elseif (!empty($_SERVER['PATH_INFO'])) {
            $path = $_SERVER['PATH_INFO'];
        } elseif (!empty($_SERVER['ORIG_PATH_INFO'])) {
            $path = $_SERVER['ORIG_PATH_INFO'];
        } else {
            return '/';
        }

        $base = '/oauth/';
        if (strpos($path, $base) === 0) {
            $path = '/' . substr($path, strlen($base));
        }

        if (strpos($path, '/index.php') === 0) {
            $path = substr($path, 10);
        }

        if (empty($path) || $path === '/') {
            return '/';
        }
        $path = '/' . ltrim($path, '/');
        if ($path !== '/' && substr($path, -1) === '/') {
            $path = rtrim($path, '/');
        }

        return $path;
    }

    public function route()
    {
        if (!isset($_SERVER['REQUEST_METHOD']) || $_SERVER['REQUEST_METHOD'] !== 'GET') {
            http_response_code(405);
            header('Allow: GET');
            $this->debugLog("Invalid request method: " . ($_SERVER['REQUEST_METHOD'] ?? 'NONE'));
            return;
        }

        $path = $this->getRequestPath();

        $this->debugLog("OAuth Debug - REQUEST_URI: " . ($_SERVER['REQUEST_URI'] ?? 'N/A'));
        $this->debugLog("OAuth Debug - Parsed path: " . $path);
        $this->debugLog("OAuth Debug - REQUEST_METHOD: " . $_SERVER['REQUEST_METHOD']);
        $this->debugLog("OAuth Debug - GET params: " . json_encode($_GET));

        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            if (in_array($path, ['/auth', '/authorize'])) {
                $this->debugLog("OAuth Debug - Routing to handleAuth");
                return $this->handleAuth();
            } elseif (in_array($path, ['/callback', '/redirect'])) {
                $this->debugLog("OAuth Debug - Routing to handleCallback");
                return $this->handleCallback();
            }
        }

        $this->debugLog("OAuth Debug - No route matched! Path: " . $path);
        http_response_code(404);
    }
}

// Initialize and route request
$handler = new SveltiaCMSAuthHandler();
$handler->route();
