<?php
include "header.php";

//Initialize variables

$name = $email = '';
$errors = [];

// Database connection
$conn = mysqli_connect("localhost", "root", "", "e-commerce");
if (!$conn) {
  die("Connection failed:" . mysqli_connect_error());
}

// Handle form submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["Signup"])) {
  // Sanitize input

  $name = trim($_POST['name'] ?? '');
  $email = filter_var(trim($_POST['email'] ?? ''), FILTER_SANITIZE_EMAIL);
  $password = $_POST['password'] ?? '';
  $cpassword = $_POST['cpassword'] ?? '';

  // Validate Name
  if (empty($name)) {
    $errors['name'] = "Name is required.";
  }
  // Validate Email
  if (empty($email)) {
    $errors['email'] = "Email is required.";
  } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors['email'] = "Invalid email format.";
  }

  // Validate Password
  if (empty($password)) {
    $errors['password'] = "Password is required.";
  } elseif (strlen($password) < 4) {
    $errors['password'] = "Password must be at least 4 characters.";
  }

  // Validate Confirm Password
  if (empty($cpassword)) {
    $errors['cpassword'] = "Confirm Password is required.";
  } elseif ($password !== $cpassword) {
    $errors['cpassword'] = "Passwords do not match.";
  }

  // Check if email already exists
  if (empty($errors)) {
    $checksql = "SELECT id FROM signup WHERE email = ?";
    $stmt = mysqli_prepare($conn, $checksql);
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);

    if (mysqli_stmt_num_rows($stmt) > 0) {
      $errors['email'] = "Email already exists.";
    }
    mysqli_stmt_close($stmt);
  }

  // If no errors, proceed with registration
  if (empty($errors)) {
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    $insert_sql = "INSERT INTO signup (name, email, password) VALUES (?, ?, ?)";
    $stmt = mysqli_prepare($conn, $insert_sql);
    mysqli_stmt_bind_param($stmt, "sss", $name, $email, $hashed_password);

    if (mysqli_stmt_execute($stmt)) {
      echo "<script>alert('Registration successful'); window.location.href='login.php';</script>";
      exit;
    } else {
      $errors['general'] = "Something went wrong, please try again.";
    }
    mysqli_stmt_close($stmt);
  }
}

mysqli_close($conn);
?>
<link rel="stylesheet" href="sign.css">
<div class="container">
  <div class="row justify-content-center">
    <div class="col-md-5">
      <div class="card">
        <h2 class="card-title text-center">Register</h2>
        <div class="card-body py-md-4">
          <?php if (!empty($errors['general'])): ?>
            <div class="alert alert-danger"><?php echo $errors['general']; ?></div>
          <?php endif; ?>
          <form action="signup.php" method="POST">
            <div class="form-group">
              <input type="text" class="form-control" id="name" placeholder="Name" name="name" value="<?php echo htmlspecialchars($name); ?>">
              <?php if (!empty($errors['name'])): ?>
                <small class="text-danger"><?php echo $errors['name']; ?></small>
              <?php endif; ?>
            </div>
            <div class="form-group">
              <input type="email" class="form-control" id="email" placeholder="Email" name="email" value="<?php echo htmlspecialchars($email); ?>">
              <?php if (!empty($errors['email'])): ?>
                <small class="text-danger"><?php echo $errors['email']; ?></small>
              <?php endif; ?>
            </div>
            <div class="form-group">
              <input type="password" class="form-control" id="password" placeholder="Password" name="password">
              <?php if (!empty($errors['password'])): ?>
                <small class="text-danger"><?php echo $errors['password']; ?></small>
              <?php endif; ?>
            </div>
            <div class="form-group">
              <input type="password" class="form-control" id="confirm-password" placeholder="Confirm Password" name="cpassword">
              <?php if (!empty($errors['cpassword'])): ?>
                <small class="text-danger"><?php echo $errors['cpassword']; ?></small>
              <?php endif; ?>
            </div>
            <div class="d-flex flex-row align-items-center justify-content -between">
              <a href="./login.php" class="mx-0">Login</a>
              <button type="submit" name="Signup" class="btn btn-primary mx-auto">Signup</button>
            </div>
          </form>
        </div>
      </div>
    </div>
  </div>
</div>