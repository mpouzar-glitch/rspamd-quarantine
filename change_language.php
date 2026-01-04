<?php
/**
 * Change Language API Endpoint
 */

session_start();
require_once 'lang_helper.php';

header('Content-Type: application/json');

if (isset($_GET['lang'])) {
    $lang = Lang::getInstance();

    if ($lang->setLanguage($_GET['lang'])) {
        echo json_encode([
            'success' => true,
            'language' => $_GET['lang'],
            'message' => 'Language changed successfully'
        ]);
    } else {
        echo json_encode([
            'success' => false,
            'message' => 'Invalid language code'
        ]);
    }
} else {
    echo json_encode([
        'success' => false,
        'message' => 'Language parameter missing'
    ]);
}
?>
