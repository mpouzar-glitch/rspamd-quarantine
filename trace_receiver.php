<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';

/**
 * Check if remote IP address is allowed to access receiver endpoints
 * @return bool True if IP is allowed, false otherwise
 */
function isAllowedReceiverIP(): bool {
    // Get real client IP address
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';

    // Handle X-Forwarded-For if behind proxy (optional, be careful with this!)
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwarded_ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $client_ip = trim($forwarded_ips[0]);
    }

    // Check if IP is in whitelist
    if (defined('RECEIVER_ALLOWED_IPS')) {
        $allowed_ips = RECEIVER_ALLOWED_IPS;

        // Check exact match
        if (in_array($client_ip, $allowed_ips, true)) {
            return true;
        }

        // Check CIDR ranges
        foreach ($allowed_ips as $allowed_ip) {
            // Check if it's a CIDR notation
            if (strpos($allowed_ip, '/') !== false) {
                if (ipInCIDR($client_ip, $allowed_ip)) {
                    return true;
                }
            }
        }
    }

    // Log unauthorized access attempt
    error_log(sprintf(
        'Unauthorized receiver access attempt from IP: %s (User-Agent: %s)',
        $client_ip,
        $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
    ));

    return false;
}

/**
 * Check if an IP address is within a CIDR range
 * @param string $ip IP address to check
 * @param string $cidr CIDR notation (e.g., 192.168.1.0/24)
 * @return bool
 */
function ipInCIDR(string $ip, string $cidr): bool {
    list($subnet, $mask) = explode('/', $cidr);

    // Convert IP addresses to long integers
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);

    if ($ip_long === false || $subnet_long === false) {
        return false;
    }

    // Create mask
    $mask_long = -1 << (32 - (int)$mask);

    // Compare
    return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

if (!isAllowedReceiverIP()) {
    http_response_code(403);
    echo json_encode([
        'status' => 'error',
        'message' => 'Access denied - IP not whitelisted'
    ]);
    exit;
}

$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

if (!$data) {
    http_response_code(400);
    exit;
}

try {
    $db = Database::getInstance()->getConnection();
    
    $message_id = $data['message-id'] ?? $data['message_id'] ?? null;
    $queue_id = $data['queue-id'] ?? $data['queue_id'] ?? null;
    $sender = $data['from'] ?? $data['sender'] ?? '';
    
    // Recipients - OPRAVA: správné zpracování pole
    if (isset($data['rcpt'])) {
        $recipients = is_array($data['rcpt']) ? implode(', ', $data['rcpt']) : $data['rcpt'];
    } elseif (isset($data['recipients'])) {
        $recipients = is_array($data['recipients']) ? implode(', ', $data['recipients']) : $data['recipients'];
    } else {
        $recipients = '';
    }
    
    $subject = $data['subject'] ?? '';
    $ip_address = $data['ip'] ?? '';
    $country = getCountryCodeForIp($ip_address);
    $authenticated_user = $data['user'] ?? $data['authenticated_user'] ?? null;
    $action = $data['action'] ?? 'unknown';
    $score = floatval($data['score'] ?? 0);
    $hostname = $data['hostname']
        ?? $data['rspamd_server']
        ?? ($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? '');

    $headers_from = '';
    if (isset($data['header_from'])) {
        $headers_from = is_array($data['header_from']) ? implode(', ', $data['header_from']) : $data['header_from'];
    } elseif (isset($data['headers_from'])) {
        $headers_from = is_array($data['headers_from']) ? implode(', ', $data['headers_from']) : $data['headers_from'];
    } elseif (!empty($sender)) {
        $headers_from = $sender;
    }

    $headers_to = '';
    if (isset($data['header_to'])) {
        $headers_to = is_array($data['header_to']) ? implode(', ', $data['header_to']) : $data['header_to'];
    } elseif (isset($data['headers_to'])) {
        $headers_to = is_array($data['headers_to']) ? implode(', ', $data['headers_to']) : $data['headers_to'];
    } elseif (!empty($recipients)) {
        $headers_to = $recipients;
    }

    $size_bytes = isset($data['size']) ? (int)$data['size'] : null;
    $metadata_json = json_encode($data, JSON_UNESCAPED_UNICODE);
    
    // Parse symbols - OPRAVA
    $symbols_str = '';
    
    if (isset($data['symbols'])) {
        $symbols = [];
        
        // Pokud je to string
        if (is_string($data['symbols'])) {
            $symbols_str = $data['symbols'];
        }
        // Pokud je to pole
        elseif (is_array($data['symbols'])) {
            foreach ($data['symbols'] as $key => $value) {
                // Pokud klíč není číslo - je to název symbolu
                if (!is_numeric($key)) {
                    if (is_array($value) && isset($value['score'])) {
                        $symbols[] = $key . '(' . number_format($value['score'], 2) . ')';
                    } elseif (is_numeric($value)) {
                        $symbols[] = $key . '(' . number_format($value, 2) . ')';
                    } else {
                        $symbols[] = $key;
                    }
                }
                // Pokud je klíč číslo, zkusíme extrahovat name
                else {
                    if (is_array($value) && isset($value['name'])) {
                        $name = $value['name'];
                        $score_val = $value['score'] ?? 0;
                        $symbols[] = $name . '(' . number_format($score_val, 2) . ')';
                    }
                }
            }
            
            if (empty($symbols)) {
                // Fallback - uložíme jako JSON pokud parsování selhalo
                $symbols_str = json_encode($data['symbols']);
            } else {
                $symbols_str = implode(', ', $symbols);
            }
        }
    }
    
    // OPRAVA: Explicitně definovat parametry
    $params = [
        $message_id,
        $queue_id,
        $sender,
        $recipients,  // Nyní je to string, ne pole
        $subject,
        $ip_address,
        $country,
        $authenticated_user,
        $action,
        $score,
        $symbols_str,
        $size_bytes,
        $headers_from,
        $headers_to,
        $hostname,
        $metadata_json
    ];
    
    // Insert into message_trace (všechny zprávy)
    $stmt = $db->prepare("
        INSERT INTO message_trace (message_id, queue_id, sender, recipients, subject, ip_address,
                                  country, authenticated_user, action, score, symbols, size_bytes,
                                  headers_from, headers_to, hostname, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ");
    
    $result = $stmt->execute($params);
    
    if ($result) {
        $trace_id = $db->lastInsertId();
        
        http_response_code(200);
        echo json_encode(['status' => 'ok', 'trace_id' => $trace_id]);
    } else {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Insert failed']);
    }
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => $e->getMessage()]);
}
?>
