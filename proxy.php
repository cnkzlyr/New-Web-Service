<?php
// proxy.php - M3U / HLS çalma listeleri için basit PHP proxy
//
// Güvenlik önlemleri:
//  * Yalnızca http/https adresleri (file://, php://, ftp:// vb. reddedilir → yerel dosya okuma engellenir)
//  * Hedef ana bilgisayarın TÜM IP adresleri özel/ayrılmış aralıkta olmamalı (SSRF: 127.0.0.1, 10.x,
//    192.168.x, 169.254.169.254 bulut meta verisi vb. reddedilir)
//  * Yönlendirmeler takip edilmez (yönlendirmeyle iç ağa sıçrama engellenir)
//  * Zaman aşımı ve yanıt boyutu sınırı
//  * İsteğe bağlı: PROXY_ALLOWED_HOSTS ortam değişkeniyle (virgülle ayrılmış) izinli alan adı listesi

// Tarayıcıdan yalnızca kendi sitenizden çağrılacaksa açın:
// header("Access-Control-Allow-Origin: https://sizin-alan-adiniz.com");

const PROXY_TIMEOUT_SEC = 15;
const PROXY_MAX_BYTES   = 5 * 1024 * 1024; // 5 MB

function proxy_fail(int $code, string $msg): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=UTF-8');
    die(json_encode(['error' => $msg], JSON_UNESCAPED_UNICODE));
}

$target_url = $_GET['url'] ?? '';
if (!is_string($target_url) || $target_url === '' || !filter_var($target_url, FILTER_VALIDATE_URL)) {
    proxy_fail(400, 'Geçerli bir hedef URL belirtilmedi.');
}

$parts  = parse_url($target_url);
$scheme = strtolower($parts['scheme'] ?? '');
$host   = strtolower(rtrim($parts['host'] ?? '', '.'));
if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
    proxy_fail(400, 'Yalnızca http ve https adresleri desteklenir.');
}
if (isset($parts['user']) || isset($parts['pass'])) {
    proxy_fail(400, 'Kimlik bilgisi içeren adresler desteklenmez.');
}

$allowed = array_filter(array_map('trim', explode(',', strtolower((string)getenv('PROXY_ALLOWED_HOSTS')))));
if ($allowed) {
    $ok = false;
    foreach ($allowed as $a) {
        if ($host === $a || str_ends_with($host, '.' . $a)) { $ok = true; break; }
    }
    if (!$ok) proxy_fail(403, 'Bu alan adına izin verilmiyor.');
}

// Ana bilgisayarı çöz; tüm adresler genel (public) olmalı
$ips = [];
$bare = trim($host, '[]');
if (filter_var($bare, FILTER_VALIDATE_IP)) {
    $ips[] = $bare;
} else {
    foreach ((array)@dns_get_record($host, DNS_A | DNS_AAAA) as $r) {
        if (!empty($r['ip']))   $ips[] = $r['ip'];
        if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
    }
}
if (!$ips) proxy_fail(502, 'Hedef ana bilgisayar çözülemedi.');
foreach ($ips as $ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        proxy_fail(403, 'Özel veya ayrılmış ağ adreslerine erişim engellendi.');
    }
}

// Gerçek isteği yaparken tarayıcı gibi davranalım
$context = stream_context_create([
    'http' => [
        'method'          => 'GET',
        'header'          => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36\r\n",
        'timeout'         => PROXY_TIMEOUT_SEC,
        'follow_location' => 0,
        'ignore_errors'   => false,
    ],
]);

$fp = @fopen($target_url, 'rb', false, $context);
if ($fp === false) {
    proxy_fail(502, 'Hedef sunucuya ulaşılamadı veya hata döndürdü.');
}
$content = stream_get_contents($fp, PROXY_MAX_BYTES + 1);
fclose($fp);
if ($content === false) {
    proxy_fail(502, 'Hedef sunucudan yanıt okunamadı.');
}
if (strlen($content) > PROXY_MAX_BYTES) {
    proxy_fail(413, 'Yanıt boyutu sınırı aşıldı.');
}

// Gelen içeriğin M3U olduğunu varsayarak doğru başlığı gönderiyoruz
header('Content-Type: application/x-mpegURL; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
echo $content;
