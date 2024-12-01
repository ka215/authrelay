<?php
// セキュリティヘッダーの設定
$nonce = base64_encode(random_bytes(16)); // nonceの生成
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-$nonce'; img-src 'self';");
header("Referrer-Policy: no-referrer");
header("Permissions-Policy: camera=(), microphone=(), geolocation=()");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
// header("X-XSS-Protection: 1; mode=block");// 最新のブラウザでは非推奨

require 'vendor/autoload.php'; // JWTライブラリが必要な場合に読み込み

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

// 選択された言語を取得（デフォルトは 'en'）
$selectedLang = htmlspecialchars($_REQUEST['lang'] ?? 'en', ENT_QUOTES, 'UTF-8');
$langFile = __DIR__ . "/languages/{$selectedLang}.php";
// 言語リソースを読み込む
if (file_exists($langFile)) {
    $lang = include $langFile;
} else {
    $lang = include __DIR__ . '/languages/en.php'; // デフォルトを日本語に
}
// テンプレート関数を定義
function __($key, array $allowedTags = []) {
    global $lang;
    // 翻訳テキストを取得
    $translation = $lang[$key] && !empty($lang[$key]) ? $lang[$key] : $key;
    // 許可するタグを文字列形式に変換
    $allowedTagsString = '';
    if (!empty($allowedTags)) {
        $allowedTagsString = '<' . implode('><', $allowedTags) . '>';
    }
    // 許可されたタグ以外はエスケープ
    $translation = strip_tags($translation, $allowedTagsString);
    return $translation;    
}

// ページ設定
$presetRoles = [
    'subscriber'  => __('Subscriber (Readonly User)'), // '購読者（Readonly User）',
    'editor'      => __('Editor (Editable User)'), // '編集者（Editable User）',
    'substituter' => __('Substituter (Substitute Editor)'), // '代用者（Substitute Editor）',
    'admin'       => __('Administrator') // '管理者（Administrator）'
];
$presetAlgorithms = [
    'HS256' => __('HS256'),
    'HS384' => __('HS384'),
    'HS512' => __('HS512'),
    'RS256' => __('RS256 (with Private Key)'), // 'RS256（要秘密鍵）',
    'RS384' => __('RS384 (with Private Key)'), // 'RS384（要秘密鍵）',
    'RS512' => __('RS512 (with Private Key)'), // 'RS512（要秘密鍵）',
    'ES256' => __('RS256 (with Private Key)'), // 'ES256（要秘密鍵）',
    'ES384' => __('RS384 (with Private Key)'), // 'ES384（要秘密鍵）'
    //'ES512' => __('RS512 (with Private Key)'), // 'ES512（要秘密鍵）' // ES512はサポートされていない
];
// Rolesの複数選択を許可するかどうかのフラグ（?mr=1のクエリ文字列で制御可能）
$isMultipleSelect = isset($_REQUEST['mr']) ? boolval($_REQUEST['mr']) : false;
// 秘密鍵ファイルの取り扱い（秘密鍵のアップロードを許可するかどうか）
$isUploadablePrivateKey = false;
$isValidRedirectUrl = null;
$secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';

// 入力値を取得・検証・正規化
$userId = filter_input(INPUT_POST, 'userId', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? 'dummy-user';
$secretKey = filter_input(INPUT_POST, 'secretKey', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? 'your-secret-key';
$redirectUrl = filter_input(INPUT_POST, 'redirectUrl', FILTER_VALIDATE_URL) ?? 'http://localhost:3000';
$roles = filter_input(INPUT_POST, 'roles', FILTER_DEFAULT, FILTER_REQUIRE_ARRAY) ?? ['subscriber'];
$type = filter_input(INPUT_POST, 'type', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? 'jwt';
$algorithm = filter_input(INPUT_POST, 'algorithm', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? 'HS256';
$privateKeyPath = filter_input(INPUT_POST, 'privateKeyPath', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? '';
$privateKeyFile = $_FILES['privateKeyFile'] ?? null;
$via = filter_input(INPUT_POST, 'via', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? 'http';
$action = filter_input(INPUT_POST, 'action', FILTER_SANITIZE_FULL_SPECIAL_CHARS) ?? 'try';

// リダイレクトURLの正規化処理
if ($redirectUrl && filter_var($redirectUrl, FILTER_VALIDATE_URL)) {
    $redirectUrlComponents = parse_url($redirectUrl);

    // 必須コンポーネントをチェック
    $scheme = $redirectUrlComponents['scheme'] ?? 'http';
    $host = $redirectUrlComponents['host'] ?? '';
    $port = $redirectUrlComponents['port'] ?? '';
    $path = $redirectUrlComponents['path'] ?? '/';
    $query = $redirectUrlComponents['query'] ?? '';

    // 正規化されたURLの再構築
    $redirectUrl = sprintf(
        '%s://%s%s%s',
        $scheme,
        $host . ($port ? ":$port" : ''),
        rtrim($path, '/'), // パス末尾のスラッシュを削除
        $query ? '?' . $query : ''
    );

    // ドメイン名を取得
    $cookieDomain = $host;
    if (filter_var($cookieDomain, FILTER_VALIDATE_IP)) {
        // IPアドレスの場合はドメイン名に変換
        $cookieDomain = gethostbyaddr($cookieDomain);
    }

    // URLが無効の場合のエラー処理（省略可能）
    if (!$host) {
        die(__('Invalid redirect URL'));
    }
} else {
    $redirectUrl = 'http://localhost:3000';
    $cookieDomain = 'localhost'; // デフォルト値
}

// Cookieオプションの設定
try {
    $cookieArgs = [
        'expires' => time() + 3600,
        'path' => '/',
        'domain' => $cookieDomain, // サブドメイン全体でCookieを共有する必要がある場合は先頭に `.` を付ける
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Lax'
    ];
} catch (Exception $e) {
    die(__('Cookie configuration error: ') . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
}

// セッション開始
session_start();

if ($type === 'jwt') {
    // JWTトークン生成
    $payload = [
        'iss' => 'your-app',
        'aud' => 'nuxt-app',
        'iat' => time(),
        'exp' => time() + 3600, // 1時間有効
        'userId' => $userId,
        'roles' => $roles
    ];

    if ($privateKeyFile) {
        // 秘密鍵のアップロード
        $privateKey = file_get_contents($privateKeyFile['tmp_name']);
    } else {
        // 秘密鍵の取得
        $privateKey = getPrivateKey($algorithm, $secretKey, $privateKeyPath);
    }
    try {
        $jwt = JWT::encode($payload, $privateKey, $algorithm);
    } catch (Exception $e) {
        die(__('JWT generation failed: ') . htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'));
    }

    // リダイレクト先をセット
    $headerRedirect = "Location: {$redirectUrl}";
} else {
    // ユーザーセッション
    $sessionId = session_id() ?: bin2hex(random_bytes(16));

    // リダイレクト先をセット
    $headerRedirect = "Location: {$redirectUrl}";
}

if ($action === 'commit') {
    // リダイレクト処理
    if ($via === 'http') {
        // HTTPヘッダー経由の場合
        header('Authorization: Bearer ' . ($type === 'jwt' ? $jwt : $sessionId));
        header("Roles: " . json_encode($roles));
    } elseif ($via === 'cookie') {
        // Cookie経由の場合
        if ($type === 'jwt') {
            setcookie('auth_token', $jwt, $cookieArgs); // JWTをCookieにセット
        } else {
            setcookie('auth_session', $sessionId, $cookieArgs); // セッションIDをCookieにセット
        }
        setcookie('roles', json_encode($roles), $cookieArgs); // ロールをCookieにセット
    } else {
        // 未知の接続方法の場合はエラー
        die(__('Error: Invalid connection method'));
    }
    header($headerRedirect);
    exit;
} else {
    // 指定された $redirectUrl が遷移先としてURLが存在しているかを確認する
    $isValidRedirectUrl = null;
    if (filter_var($redirectUrl, FILTER_VALIDATE_URL)) {
        $context = stream_context_create(['http' => ['timeout' => 5]]);
        $headers = @get_headers($redirectUrl, false, $context);
        $isValidRedirectUrl = $headers && strpos($headers[0], '200') !== false;
    } else {
        $isValidRedirectUrl = false;
    }

    // リクエスト情報をセット
    if ($type === 'jwt') {
        $requestValue = $jwt;
    } else {
        $requestValue = simulateSetCookie('auth_session', $sessionId, $cookieArgs);
        $requestValue .= '; ' . simulateSetCookie('roles', json_encode($roles), $cookieArgs);
    }
    $requestInfo = [
        'userId' => htmlspecialchars($userId, ENT_QUOTES, 'UTF-8'),
        'secret' => htmlspecialchars($secretKey, ENT_QUOTES, 'UTF-8'),
        'redirectUrl' => htmlspecialchars($redirectUrl, ENT_QUOTES, 'UTF-8'),
        'roles' => json_encode($roles, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_APOS),
        'type' => htmlspecialchars($type, ENT_QUOTES, 'UTF-8'),
        ($type === 'jwt' ? 'Token' : 'Cookie') => htmlspecialchars($requestValue, ENT_QUOTES, 'UTF-8')
    ];
}

// セッションを破棄
session_destroy();

// 秘密鍵の取得
function getPrivateKey($algorithm, $secretKey, $privateKeyPath) {
    if (in_array($algorithm, ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'], true)) {
        // 秘密鍵の読み込み
        $path = file_exists($privateKeyPath) 
            ? $privateKeyPath 
            : __DIR__ . '/keys/' . (strpos($algorithm, 'RS') === 0 ? 'rsa' : 'ecdsa') . '_private.pem';
        if (file_exists($path)) {
            return @file_get_contents($path);
        }
        die(sprintf(__('Error: Private key not found for algorithm %s'), $algorithm));
    }
    return $secretKey; // HMACの場合はシークレットキーをそのまま利用
}

// Cookieヘッダー文字列生成
function simulateSetCookie($name, $value, $options = []) {
    $parts = [$name . '=' . urlencode($value)];
    $parts = array_merge($parts, array_filter([
        isset($options['expires']) ? 'Expires=' . gmdate('D, d-M-Y H:i:s T', $options['expires']) : null,
        isset($options['path']) ? 'Path=' . $options['path'] : null,
        isset($options['domain']) ? 'Domain=' . $options['domain'] : null,
        !empty($options['secure']) ? 'Secure' : null,
        !empty($options['httponly']) ? 'HttpOnly' : null,
        isset($options['samesite']) ? 'SameSite=' . $options['samesite'] : null,
    ]));
    return implode('; ', $parts);
}
?>
<!DOCTYPE html>
<html lang="<?= $selectedLang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= __('AuthRelay') ?></title>
    <meta description="<?= __('This app acts as a mock to generate and pass credentials to the next application or service.') ?>">
    <link rel="stylesheet" href="styles.css">
</head>
<body>
    <header>
        <h1><?= __('Authentication Relay Mockup') ?></h1>
    </header>
    <main>
        <p>
            <?= __('This page is a mockup for inheriting the authentication process of a web application, and simulates redirection to continue authentication information to any application after authentication.') ?><br>
            <?= __('This mock is intended for web pages such as the login screen or the dashboard after logging in, and allows you to try connecting to a specified web application by choosing from two methods for passing authentication information from there: JWT token format or Cookie format.') ?><br>
        </p>
        <form method="post" action="index.php">
            <label><?= __('User ID') ?>:
                <input type="text" name="userId" value="<?= htmlspecialchars($userId, ENT_QUOTES, 'UTF-8'); ?>" required>
            </label>
            <label><?= __('Secret Key') ?>:
                <input type="text" name="secretKey" value="<?= htmlspecialchars($secretKey, ENT_QUOTES, 'UTF-8'); ?>" required>
            </label>
            <label><?= __('Redirect URL') ?>:
                <input type="text" name="redirectUrl" value="<?= htmlspecialchars($redirectUrl, ENT_QUOTES, 'UTF-8'); ?>" required>
                <?php if (!is_null($isValidRedirectUrl)): ?><span class="url-<?= $isValidRedirectUrl ? 'exists' : 'notfound'; ?>"></span><?php endif; ?>
            </label>
            <label<?php if ($isMultipleSelect): ?> class="multiple-select" data-items="<?= count($presetRoles); ?>" style="height: calc(<?= count($presetRoles); ?> * 23px);"<?php endif; ?> nonce="<?= $nonce; ?>"><?= __('Roles') ?>:
                <select name="roles[]"<?php if ($isMultipleSelect): ?> multiple<?php endif; ?>>
                  <?php foreach ($presetRoles as $roleValue => $label): ?>
                    <option value="<?= $roleValue; ?>"<?php if (in_array($roleValue, $roles, true)): ?> selected<?php endif; ?>><?= $label; ?></option>
                  <?php endforeach; ?>
                </select>
            </label>
            <div class="flex">
                <label class="short-label"><?= __('Credential Format') ?>:</label>
                <label><input type="radio" name="type" value="jwt"<?php if ($type === 'jwt'): ?> checked<?php endif; ?>><?= __('JWT (JSON Web Token)') ?></label>
                <label><input type="radio" name="type" value="cookie"<?php if ($type === 'cookie'): ?> checked<?php endif; ?>><?= __('Session Cookies') ?></label>
            </div>
            <label<?php if ($type != 'jwt'): ?> hidden<?php endif; ?>><?= __('Algorithm') ?>:
                <select name="algorithm">
                  <?php foreach ($presetAlgorithms as $algorithmValue => $label): ?>
                    <option value="<?= $algorithmValue; ?>"<?php if ($algorithm === $algorithmValue): ?> selected<?php endif; ?>><?= $label; ?></option>
                  <?php endforeach; ?>
                </select>
            </label>
            <label class="flex"<?php if ($type != 'jwt'): ?> hidden<?php endif; ?>>
              <?php if ($isUploadablePrivateKey): ?>
                <?= __('Private Key File') ?>:
                <input type="file" name="privateKeyFile" accept=".key,.pem">
              <?php else: ?>
                <?= __('Private Key File Path') ?>:
                <input type="text" name="privateKeyPath" value="<?= htmlspecialchars($privateKeyPath, ENT_QUOTES, 'UTF-8'); ?>" placeholder="/path/to/privateKey.pem">
              <?php endif; ?>
            </label>
            <div class="flex">
                <label class="short-label"><?= __('Connection Method') ?>:<a name="help" class="toggle-help" data-for="help-connection"></a></label>
                <label><input type="radio" name="via" value="http"<?php if ($via === 'http'): ?> checked<?php endif; ?>><?= __('Include in HTTP header') ?></label>
                <label><input type="radio" name="via" value="cookie"<?php if ($via === 'cookie'): ?> checked<?php endif; ?>><?= __('Auto-Send using Cookies') ?></label>
            </div>
            <div id="help-connection" class="help-container" hidden>
                <table>
                    <thead>
                        <tr><th><?= __('Connection Method') ?></th><th><?= __('Include in HTTP header') ?></th><th><?= __('Auto-Send using Cookies') ?></th></tr>
                    </thead>
                    <tbody>
                        <tr><td><strong><?= __('Connection Specification') ?></strong></td><td><?= __('Redirect with JWT token or session ID included in the HTTP header') ?></td><td><?= __('Save JWT token or session information in a cookie and automatically send it to the redirect destination') ?></td></tr>
                        <tr><td><strong><?= __('Security') ?></strong></td><td><?= __('High resistance to CSRF') ?></td><td><?= __('CSRF countermeasures required (<code>SameSite</code> is mandatory)', ['code']) ?></td></tr>
                        <tr><td><strong><?= __('Ease of Implementation') ?></strong></td><td><?= __('Requires manual header configuration') ?></td><td><?= __('Browser automatically sends cookies') ?></td></tr>
                        <tr><td><strong><?= __('State Management Flexibility') ?></strong></td><td><?= __('Frontend can manage tokens') ?></td><td><?= __('Server-side session management is easier') ?></td></tr>
                        <tr><td><strong><?= __('Token Visibility') ?></strong></td><td><?= __('Easily accessible via JavaScript') ?></td><td><?= __('Can be hidden from JavaScript using <code>HttpOnly</code>', ['code']) ?></td></tr>
                        <tr><td><strong><?= __('Use Case') ?></strong></td><td><?= __('Suitable for direct communication with API clients') ?></td><td><?= __('Suitable for user sessions') ?></td></tr>
                    </tbody>
                </table>                  
            </div>
            <button type="button" name="try" value="try"><?= __('Simulate (Dry-Run)') ?></button>
            <button type="submit" name="commit" value="commit"<?php if (!$isValidRedirectUrl): ?> disabled<?php endif; ?>><?= __('Connect') ?></button>
            <button type="button" name="reset" value="reset"><?= __('Reset') ?></button>
            <input type="hidden" name="action" value="<?= $action; ?>">
            <input type="hidden" name="mr" value="<?= $isMultipleSelect ? '1' : '0'; ?>">
            <input type="hidden" name="lang" value="<?= $selectedLang; ?>">
        </form>
        <hr />
        <h2><?= __('Request Information') ?></h2>
        <div>
            <pre id="request-info"></pre>
        </div>
    </main>
    <footer>
        <nav>
            <a href="?lang=ja"<?php if ($selectedLang === 'ja'): ?> class="active"<?php endif; ?>>日本語</a>
            <a href="?lang=en"<?php if ($selectedLang === 'en'): ?> class="active"<?php endif; ?>>English</a>
        </nav>
        <p>&copy; 2024 AuthRelay powered by MAGIC METHODS</p>
    </footer>
    <script nonce="<?= $nonce; ?>">
        // 遷移先URLフィールドのサイズ調整
        const redirectUrlInput = document.querySelector('input[name="redirectUrl"]');
        redirectUrlInput.size = redirectUrlInput.value.length + 1;

        // 接続方式変更時の処理
        document.querySelectorAll('input[name="type"]').forEach((radio) => {
            radio.addEventListener('change', (event) => {
                const isJwt = event.target.value === 'jwt';
                const algElm = document.querySelector('select[name="algorithm"]');
                if (algElm) {
                    algElm.closest('label').hidden = !isJwt;
                }
                const pkpElm = document.querySelector('input[name="privateKeyPath"]');
                if (pkpElm) {
                    pkpElm.closest('label').hidden = !isJwt;
                }
                const pkfElm = document.querySelector('input[name="privateKeyFile"]');
                if (pkfElm) {
                    pkfElm.closest('label').hidden = !isJwt;
                }
            });
        })

        // リクエスト情報の表示
        const requestInfo = <?= json_encode($requestInfo, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES); ?>;
        document.getElementById('request-info').textContent = JSON.stringify(requestInfo, null, 2);

        // ボタン要素の定義
        const btnTry = document.querySelector('button[name="try"]');
        const btnCommit = document.querySelector('button[name="commit"]');
        const btnReset = document.querySelector('button[name="reset"]');

        // 入力フィールドのバリデーション
        const checkValidity = (formElement) => {
            const invalidElements = Array.from(formElement.elements).filter(element => !element.checkValidity());
            invalidElements.forEach(element => {
                element.classList.add('error');
                // 各要素にエラーメッセージを追加
                const errorMessage = element.validationMessage || 'Invalid input';
                let errorElement = element.nextElementSibling;
                if (!errorElement || !errorElement.classList.contains('error-message')) {
                    errorElement = document.createElement('span');
                    errorElement.className = 'error-message';
                    element.after(errorElement);
                    const elmRect = element.getBoundingClientRect();
                    console.log(elmRect);
                    errorElement.style.left = `${elmRect.right - 14}px`;
                }
                errorElement.textContent = errorMessage;
            });
            invalidElements[0]?.focus(); // 最初のエラー要素にフォーカス
            btnCommit.disabled = invalidElements.length > 0;
            return invalidElements.length === 0;
        };

        // ヘルプテキストの表示切替
        document.querySelectorAll('.toggle-help').forEach((link) => {
            link.addEventListener('click', (event) => {
                const targetId = event.target.getAttribute('data-for');
                const targetElm = document.getElementById(targetId);
                if (targetElm) {
                    targetElm.hidden = !targetElm.hidden;
                }
            });
        });

        // 「リクエスト確認」ボタンのイベントリスナー
        btnTry.addEventListener('click', (event) => {
            event.preventDefault();
            const formElement = event.target.form
            document.querySelector('input[name="action"]').value = 'try';
            if (checkValidity(formElement)) {
                event.target.form.submit();
            }
        });

        // 「接続する」ボタンのイベントリスナー
        btnCommit.addEventListener('click', (event) => {
            event.preventDefault();
            const formElement = event.target.form
            document.querySelector('input[name="action"]').value = 'commit';
            if (checkValidity(formElement)) {
                event.target.form.submit();
            }
        });

        // 「リセット」ボタンのイベントリスナー
        btnReset.addEventListener('click', (event) => {
            event.preventDefault();
            location.href = `${location.pathname}?lang=<?= $selectedLang ?>&mr=${document.querySelector('input[name="mr"]').value}&${new Date().getTime()}`;
        });
    </script>
</body>
</html>