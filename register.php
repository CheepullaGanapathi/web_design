<?php
// Enable error reporting for debugging
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Database connection
$conn = new mysqli('localhost', 'root', '', 'registration_db'); // Update database name if needed

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Ensure request method is POST
if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    die("Method Not Allowed");
}

// Check if all form fields are set
if (empty($_POST['first_name']) || empty($_POST['last_name']) || empty($_POST['email']) || empty($_POST['password']) || empty($_POST['gender']) || empty($_POST['country'])) {
    die("All fields are required.");
}

// Get and sanitize form data
$first_name = trim($_POST['first_name']);
$last_name = trim($_POST['last_name']);
$email = trim($_POST['email']);
$password = trim($_POST['password']);
$gender = trim($_POST['gender']);
$country = trim($_POST['country']);

// Validate first and last name (only letters and spaces allowed)
if (!preg_match("/^[a-zA-Z ]+$/", $first_name) || !preg_match("/^[a-zA-Z ]+$/", $last_name)) {
    die("Invalid name format. Only letters and spaces are allowed.");
}

// Validate email format
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("Invalid email format.");
}

// Validate password strength (minimum 6 characters)
if (strlen($password) < 4) {
    die("Password must be at least 4 characters long.");
}

// Check if email already exists
$check_email = $conn->prepare("SELECT id FROM users WHERE email = ?");
$check_email->bind_param("s", $email);
$check_email->execute();
$check_email->store_result();

if ($check_email->num_rows > 0) {
    die("Email is already registered. Please use a different email.");
}
$check_email->close();

// Hash the password securely
$hashed_password = password_hash($password, PASSWORD_BCRYPT);

// Prepare SQL query to insert user data
$stmt = $conn->prepare("INSERT INTO users (first_name, last_name, email, password, gender, country) VALUES (?, ?, ?, ?, ?, ?)");
$stmt->bind_param("ssssss", $first_name, $last_name, $email, $hashed_password, $gender, $country);

// Execute the query and redirect to success page
if ($stmt->execute()) {
    header("Location:success.html");
    exit();
} else {
    die("Error: " . $stmt->error);
}

// Close the statement and connection
$stmt->close();
$conn->close();
?>
