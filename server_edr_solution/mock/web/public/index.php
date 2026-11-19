<?php
declare(strict_types=1);

header('Content-Type: text/html; charset=utf-8');

$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
$proto = $_SERVER['SERVER_PROTOCOL'] ?? 'unknown';
$esc = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hello from web.dev.local</title>
</head>
<body>
  <h1>Hello, world</h1>
  <p>Served by nginx and PHP <?= $esc(PHP_VERSION) ?> on <?= $esc(gethostname() ?: 'unknown') ?>.</p>
  <p>Connection: <?= $https ? 'HTTPS' : 'plain HTTP' ?>, <?= $esc($proto) ?>.</p>
</body>
</html>
