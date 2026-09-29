<?php

// Run: php -d zend.assertions=1 -d assert.exception=1 test.php
PHP_SAPI === 'cli' || exit;
require __DIR__ . '/index.php';

$allowed = 'example.com, *.sub.org, bad*.net, ';
assert(is_domain_allowed('example.com', $allowed));
assert(is_domain_allowed('EXAMPLE.com', $allowed));
assert(!is_domain_allowed('www.example.com', $allowed));
assert(is_domain_allowed('sub.org', $allowed));
assert(is_domain_allowed('a.b.sub.org', $allowed));
assert(!is_domain_allowed('evilsub.org', $allowed));
assert(!is_domain_allowed('sub.org.evil.com', $allowed));
assert(!is_domain_allowed('badx.net', $allowed));
assert(!is_domain_allowed('exa mple.com', $allowed));
assert(!is_domain_allowed('', $allowed));
assert(!is_domain_allowed(null, $allowed));
assert(!is_domain_allowed(['example.com'], $allowed));
assert(!is_domain_allowed('example.com', ''));

assert(request_path('/oauth/authorize?provider=github&site_id=x') === '/authorize');
assert(request_path('/oauth/callback/') === '/callback');
assert(request_path('/oauth/index.php/callback') === '/callback');
assert(request_path('/oauth/') === '/');
assert(request_path('/oauth') === '/oauth');
assert(request_path('/auth') === '/auth');

assert(!is_public_ip('127.0.0.1'));
assert(!is_public_ip('10.0.0.1'));
assert(!is_public_ip(null));
assert(is_public_ip('140.82.112.3'));

assert(strpos(sanitize_debug_message('?code=abc&state=def'), 'abc') === false);
assert(strpos(sanitize_debug_message(['client_secret' => 's3cr3t']), 's3cr3t') === false);

// Hostile error text must stay inside the JS string and survive the JSON round-trip
$error = "it's \"bad\" </script><script>alert(1)</script> & \\n";
ob_start();
output_html('github', ['error' => $error, 'errorCode' => 'X']);
$html = ob_get_clean();
assert(substr_count($html, '</script>') === 1);
assert(preg_match('/postMessage\((".*?"), origin\)/', $html, $m) === 1);
$message = json_decode($m[1]);
assert(strpos($message, 'authorization:github:error:') === 0);
assert(json_decode(substr($message, strlen('authorization:github:error:')), true)['error'] === $error);

echo "ok\n";
