<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration Form</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
    <?php
if (isset($_POST["submit"])) {
    $fullName = $_POST["fullname"];
    $email = $_POST["email"];
    $password = $_POST["password"];
    $passwordRepeat = $_POST["repeat_password"];
    $personalId = $_POST["personal_id"];
    
    $passwordHash = password_hash($password, PASSWORD_DEFAULT);

    $errors = array();
    
    if (empty($fullName) && empty($email) && empty($password) && empty($passwordRepeat) && empty($personalId)) {
        array_push($errors, "All fields are required");
    } else {
        if (empty($fullName) || empty($email) || empty($password) || empty($passwordRepeat) || empty($personalId)) {
            array_push($errors, "All fields are required");
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            array_push($errors, "Email is not valid");
        }
        
        if (strlen($password) < 8) {
            array_push($errors, "Password must be at least 8 characters long");
        }
        
        if ($password !== $passwordRepeat) {
            array_push($errors, "Password does not match");
        }
        
        if (!is_numeric($personalId) || strlen($personalId) !== 8) {
            array_push($errors, "Personal ID must be 8 numbers");
        }
        
        // Check if fullname contains at least two strings
        $fullnameWords = explode(' ', $fullName);
        if (count($fullnameWords) < 2) {
            array_push($errors, "Full Name must contain at least two strings");
        }
        
        // Check if personal ID exists in the employees table
        require_once "database.php";
        $sql = "SELECT * FROM employees WHERE personalId = ?";
        $stmt = mysqli_stmt_init($conn);
        if (mysqli_stmt_prepare($stmt, $sql)) {
            mysqli_stmt_bind_param($stmt, "s", $personalId);
            mysqli_stmt_execute($stmt);
            $result = mysqli_stmt_get_result($stmt);
            if (mysqli_num_rows($result) == 0) {
                array_push($errors, "Personal ID not found");
            } else {
                $employee = mysqli_fetch_array($result, MYSQLI_ASSOC);
                if ($employee['role'] != 'admin') {
                    array_push($errors, "You are not an admin");
                }
            }
        } else {
            array_push($errors, "Database error");
        }
    }

    if (count($errors) > 0) {
        foreach ($errors as $error) {
            echo "<div class='alert alert-danger'>$error</div>";
        }
    } else {
        // Insert user into the users table
        $sql = "INSERT INTO users (personal_id, full_name, email, password) VALUES (?, ?, ?, ?)";
        $stmt = mysqli_stmt_init($conn);
        if (mysqli_stmt_prepare($stmt, $sql)) {
            mysqli_stmt_bind_param($stmt, "ssss", $personalId, $fullName, $email, $passwordHash);
            mysqli_stmt_execute($stmt);
            echo "<div class='alert alert-success'>You are registered successfully.</div>";
        } else {
            echo "Something went wrong";
        }
    }
}
?>
        <h2 style="text-align: center; font: Times New Roman">Welcome to <strong>VSQL</strong></h2>
        <div class="img-container" style="text-align: center;">
            <img src="TTs.png" class="img" style="max-width: 30%; height: auto;" alt="Logo">
        </div>
        <form action="registration.php" method="post">
            <div class="form-group">
                <input type="text" class="form-control" name="fullname" placeholder="Full Name :">
            </div>
            <div class="form-group">
                <input type="email" class="form-control" name="email" placeholder="Email :">
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="password" placeholder="Password :">
            </div>
            <div class="form-group">
                <input type="password" class="form-control" name="repeat_password" placeholder="Repeat Password :">
            </div>
            <div class="form-group">
                <input type="number" class="form-control" name="personal_id" placeholder="Personal ID :">
            </div>
            <div class="form-btn" style="text-align: center">
                <input type="submit" class="btn btn-primary" value="Register" name="submit">
            </div>
        </form>
        <div>
            <hr>
            <div><p>Already Registered <a href="http://127.0.0.1/login-register-main/">Login Here</a></p></div>
        </div>
    </div>
</body>
</html>
