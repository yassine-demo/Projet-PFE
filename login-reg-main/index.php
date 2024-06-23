<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login VSQL</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
    <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="container">
<?php
if (isset($_POST["login"])) {
    $email = $_POST["email"];
    $password = $_POST["password"];
    $personalId = $_POST["personal_id"]; // Added line to get personal ID
    require_once "database.php";
    $sql = "SELECT * FROM users WHERE email = '$email' AND personal_id = '$personalId'"; 
    $result = mysqli_query($conn, $sql);
    $user = mysqli_fetch_array($result, MYSQLI_ASSOC);
    if ($user) {
        if (password_verify($password, $user["password"])) {
            session_start();
            $_SESSION["user"] = "yes";
            header("Location: http://127.0.0.1:8000");
            die();
        } else {
            echo "<div class='alert alert-danger'>Password does not match</div>";
        }
    } else {
        echo "<div class='alert alert-danger'>Email or Personal ID does not match</div>"; // Modified error message
    }
}
?>
<h2 style="text-align: center;">Welcome to <strong>SQLShieldPro</strong></h2>
<div class="img-container" style="text-align: center;">
    <img src="TTs.png" class="img" style="max-width: 30%; height: auto;" alt="Logo">
</div>

<form action="login.php" method="post" class="forms">
    <div class="form-group">
        <input type="email" placeholder="Enter Email:" name="email" class="form-control">
    </div>
    <div class="form-group">
        <input type="password" placeholder="Enter Password:" name="password" class="form-control">
    </div>
    <div class="form-group">
        <input type="text" class="form-control" name="personal_id" placeholder="Personal ID :"> <!-- Added input field for personal ID -->
    </div>
    <div class="form-btn" style="text-align: center">
        <input type="submit" value="Login" name="login" class="btn btn-primary">
    </div>
</form>
<hr>
<div><p>Not registered yet <a href="registration.php">Register Here</a></p></div>
</div>
</body>
</html>
