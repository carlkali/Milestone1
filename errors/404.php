<?php
http_response_code(404);
$baseUrl = '/secwb/Milestone1';
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Page Not Found</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #0f172a;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }
    .error-card {
      background: #fff;
      border-radius: 24px;
      padding: 48px 40px;
      max-width: 480px;
      width: 100%;
      text-align: center;
      box-shadow: 0 24px 60px rgba(0,0,0,0.3);
      margin: 16px;
    }
    .error-code {
      font-size: 80px;
      font-weight: 900;
      background: linear-gradient(135deg,#7c3aed,#6d28d9);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      line-height: 1;
      margin-bottom: 8px;
    }
    .error-title {
      font-size: 22px;
      font-weight: 800;
      color: #111827;
      margin: 0 0 12px;
    }
    .error-msg {
      font-size: 14px;
      color: #6b7280;
      margin-bottom: 32px;
      line-height: 1.6;
    }
    .btn-home {
      display: inline-block;
      padding: 12px 28px;
      background: linear-gradient(135deg,#7c3aed,#6d28d9);
      color: #fff;
      border-radius: 12px;
      text-decoration: none;
      font-weight: 700;
      font-size: 15px;
    }
    .btn-home:hover { opacity: .85; }
  </style>
</head>
<body>
  <div class="error-card">
    <div class="error-code">Oops!</div>
    <h1 class="error-title">Page Not Found</h1>
    <p class="error-msg">
      The page you're looking for doesn't exist or has been moved.
    </p>
    <a href="<?= $baseUrl ?>/index.php" class="btn-home">Go to Homepage</a>
  </div>
</body>
</html>