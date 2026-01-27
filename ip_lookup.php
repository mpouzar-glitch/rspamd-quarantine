<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';
require_once __DIR__ . '/lang_helper.php';

requireAuth();

header('Content-Type: application/json; charset=utf-8');

$ip = trim($_GET['ip'] ?? '');
if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
    echo json_encode([
        'error' => 'invalid_ip',
    ]);
    exit;
}

$reverseDns = gethostbyaddr($ip);
if ($reverseDns === $ip) {
    $reverseDns = '';
}

$dnsRecords = [];
if ($reverseDns !== '') {
    $records = @dns_get_record($reverseDns, DNS_A + DNS_AAAA);
    if (is_array($records)) {
        foreach ($records as $record) {
            if (!empty($record['ip'])) {
                $dnsRecords[] = $record['ip'];
            }
            if (!empty($record['ipv6'])) {
                $dnsRecords[] = $record['ipv6'];
            }
        }
    }
}

$rdapData = [];
$rdapUrl = 'https://rdap.org/ip/' . urlencode($ip);
$context = stream_context_create([
    'http' => [
        'timeout' => 4,
        'user_agent' => 'Rspamd Quarantine',
    ],
]);
$rdapResponse = @file_get_contents($rdapUrl, false, $context);
if ($rdapResponse !== false) {
    $decoded = json_decode($rdapResponse, true);
    if (is_array($decoded)) {
        $rdapData = $decoded;
    }
}

$name = $rdapData['name'] ?? '';
$handle = $rdapData['handle'] ?? '';
$country = $rdapData['country'] ?? '';
$startAddress = $rdapData['startAddress'] ?? '';
$endAddress = $rdapData['endAddress'] ?? '';
$range = trim($startAddress . ($endAddress ? ' - ' . $endAddress : ''));
$asn = $rdapData['autnum'] ?? '';
$org = '';

if (!empty($rdapData['entities']) && is_array($rdapData['entities'])) {
    foreach ($rdapData['entities'] as $entity) {
        if (!is_array($entity)) {
            continue;
        }
        $roles = $entity['roles'] ?? [];
        if (in_array('registrant', $roles, true) || in_array('administrative', $roles, true)) {
            $org = $entity['vcardArray'][1][1][3] ?? ($entity['handle'] ?? '');
            break;
        }
    }
}

if ($org === '' && $name !== '') {
    $org = $name;
}

echo json_encode([
    'ip' => $ip,
    'reverse_dns' => $reverseDns,
    'dns' => array_values(array_unique($dnsRecords)),
    'asn' => $asn ?: $handle,
    'org' => $org,
    'country' => $country,
    'range' => $range,
]);
