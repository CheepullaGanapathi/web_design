<?php
session_start();
$conn = new mysqli('localhost', 'root', '', 'registration_db');

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Check if form data is set
if (!isset($_POST['email'], $_POST['password'])) {
    die("All fields are required.");
}

$email = $_POST['email'];
$password = $_POST['password'];

// Fetch user from database
$stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$stmt->store_result();
$stmt->bind_result($user_id, $hashed_password);
$stmt->fetch();

if ($stmt->num_rows > 0) {
    if (password_verify($password, $hashed_password)) {
        $_SESSION['user_id'] = $user_id;
        header("Location: home.html"); // Redirect to home page after login
        exit();
    } else {
        echo "Incorrect password!";
    }
} else {
    echo "User not found!";
}

$stmt->close();
$conn->close();
?>
