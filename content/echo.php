<?php
header('Content-Type: application/json');

// Get POST data as raw input
$data = file_get_contents("php://input");

// Try decoding JSON if it is JSON
$decoded = json_decode($data, true);

if ($decoded) {
    echo json_encode([
        "status" => "success",
        "received" => $decoded
    ], JSON_PRETTY_PRINT);
} else {
    echo json_encode([
        "status" => "success",
        "received_raw" => $data
    ], JSON_PRETTY_PRINT);
}
