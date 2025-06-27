<?php
session_start();
include "header.php";
$email = "";
$errors = [];
?>
<?php


// Database connection
$conn = mysqli_connect("localhost", "root", "", "e-commerce");
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// Check if form is submitted
if (isset($_POST['login'])) {
    // Sanitize and validate input
    $email = filter_var(trim($_POST['email']), FILTER_SANITIZE_EMAIL);
    $password = ($_POST['password']);

    $errors = [];

    // Validate email
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    // Validate password
    if (empty($password)) {
        $errors[] = "Password is required.";
    } elseif (strlen($password) < 4) {
        $errors[] = "Password should be at least 4 characters.";
    }

    // If there are validation errors, display them
    if (!empty($errors)) {
        foreach ($errors as $error) {
            echo $error . "<br>";
        }
        exit;
    }

    // Prepare and execute the query
    $stmt = $conn->prepare("SELECT id, password FROM signup WHERE email = ?");
    if ($stmt) {
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ( $row = $result->fetch_assoc()) {
            // Verify the password
             echo "Login successful!";
    } else {
      echo "Invalid password.";
    }
  } else {
    echo "Email not found.";
  }
  // Basic validation
  if (empty($email) || empty($password)) {
    echo "All fields are required.";
    exit;
  }
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo "Invalid email format.";
    exit;
  }
}
?>




<link rel="stylesheet" href="sign.css">

<div class="container">
  <div class="row justify-content-center">
    <div class="col-md-5">
      <div class="card">
        <h2 class="card-title text-center">Login <a href=""></a></h2>
        <div class="card-body py-md-4">
          <form class="" action="" method="POST">
            <div class="form-group">
              <input type="email" class="form-control" id="email" placeholder="Email" name="email">
              <?php if (!empty($errors['email'])): ?>
                <small class="text-danger"><?php echo $errors['email']; ?></small>
              <?php endif; ?>
            </div>

            <div class="form-group">
              <input type="password" class="form-control" id="password" placeholder="Password" name="password">
              <?php if (!empty($server['password'])): ?>
                <small class="text-danger"><?php echo $errors['password']; ?></small>
              <?php endif; ?>
            </div>
            <div class="d-flex flex-row align-items-center justify-content-between">
              <a href="./signup.php">Create Account</a>
              <button class="btn btn-success" name="login">Login</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>