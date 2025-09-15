<?php
// proxy.php - Basit bir PHP Proxy Script'i

// Güvenlik: Sadece bizim sitemizden gelen isteklere izin ver (isteğe bağlı ama önerilir)
// header("Access-Control-Allow-Origin: https://sizin-alan-adiniz.com");

// Hedef URL'yi parametre olarak alıyoruz
$target_url = $_GET['url'] ?? '';

if (empty($target_url) || !filter_var($target_url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    die(json_encode(['error' => 'Geçerli bir hedef URL belirtilmedi.']));
}

// Gerçek isteği yaparken tarayıcı gibi davranalım
$options = [
    "http" => [
        "method" => "GET",
        "header" => "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\n"
    ]
];
$context = stream_context_create($options);

// Hedef URL'den içeriği indir
$content = @file_get_contents($target_url, false, $context);

if ($content === false) {
    http_response_code(502); // Bad Gateway
    die(json_encode(['error' => 'Hedef sunucuya ulaşılamadı veya hata döndürdü.']));
}

// Gelen içeriğin M3U olduğunu varsayarak doğru başlığı gönderiyoruz
header("Content-Type: application/x-mpegURL; charset=UTF-8");
// Ve içeriği aynen geri yansıtıyoruz
echo $content;
