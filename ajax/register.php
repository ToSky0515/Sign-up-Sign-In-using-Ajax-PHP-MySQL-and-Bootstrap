<?php
session_start();

if(!empty($_SERVER["HTTP_X_REQUESTED_WITH"]) && strtolower($_SERVER["HTTP_X_REQUESTED_WITH"]) == "xmlhttprequest") {

    $errors = array();     
    $success = false;      
    $formData = array();
    parse_str($_POST["formData"], $formData);

    if(isset($_SESSION["token"]) && $_SESSION["token"] === $formData["_token"])  //if tokens match
    {
        if(trim($formData["name"]) == "")
        {
            $errors[] = "Name field can't be blank.";
        }
        if(trim($formData["email"]) == "")
        {
            $errors[] = "Email field can't be blank.";
        }
        if(!filter_var($formData["email"], FILTER_VALIDATE_EMAIL))
        {
            $errors[] = "Email must be a valid email address.";
        }
        if(trim($formData["username"]) == "")
        {
            $errors[] = "Username field can't be blank.";
        }
        if(trim($formData["password"]) == "")
        {
            $errors[] = "Password field can't be blank.";
        }

        require_once '../app/db.php';

        $check_if_user_exists = $db->prepare("SELECT id FROM users WHERE email = :email OR username = :username");
        $check_if_user_exists->execute(array(
            ":email" => $formData["email"],
            ":username" => $formData["username"]
        ));
        if($check_if_user_exists->rowCount() > 0)
        {
            $errors[] = "User with username " . $formData["username"] . " or email " . $formData["email"] . " already exists.";
        }

        if(empty($errors))
        {
            $hashed_password = password_hash($formData["password"], PASSWORD_DEFAULT);
            $create_user = $db->prepare("INSERT INTO users(name, email, username, password, created_at) VALUES(:name, :email, :username, :password, NOW())");
            $create_user->execute(array(
                ":name" => $formData["name"],
                ":email" => $formData["email"],
                ":username" => $formData["username"],
                ":password" => $hashed_password
            ));
            $user_id = $db->lastInsertId();
            $_SESSION["user"] = array(
              "id" => $user_id,
              "name" => $formData["name"],
              "email" => $formData["email"],
              "username" => $formData["username"],
              "password" => $hashed_password
            );
            $success = true;
        }
    }
    echo json_encode(array("errors" => $errors, "success" => $success));
}
