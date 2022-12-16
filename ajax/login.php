<?php
ini_set('session.cookie_httponly', 1);
session_start();

if(!empty($_SERVER["HTTP_X_REQUESTED_WITH"]) && strtolower($_SERVER["HTTP_X_REQUESTED_WITH"]) == "xmlhttprequest") {

    $errors = array();     
    $success = false;      

    $formData = array();
    parse_str($_POST["formData"], $formData);

    if(isset($_SESSION["token"]) && $_SESSION["token"] === $formData["_token"])  //if tokens match
    {

        if(trim($formData["username"]) == "")
        {
            $errors[] = "Username field can't be blank.";
        }
        if(trim($formData["password"]) == "")
        {
            $errors[] = "Password field can't be blank.";
        }

        require_once '../app/db.php';

        $check_user = $db->prepare("SELECT * FROM users WHERE username = :username OR email = :username");
        $check_user->execute(array(
           ":username" => $formData["username"]
        ));
        if($check_user->rowCount() > 0)
        {
            $user = $check_user->fetch();
            if(password_verify($formData["password"], $user["password"]))
            {
                $_SESSION["user"] = array(
                    "id" => $user["id"],
                    "name" => $user["name"],
                    "email" => $user["email"],
                    "username" => $user["username"],
                    "password" => $user["password"]
                );
                if(isset($formData["remember_me"]))
                {
                    setcookie("ajax_login_user", json_encode($_SESSION["user"]), time() + 86400, "/");
                }
                $success = true;
            }
        }  else $errors[] = "Incorrect username/password.";
    }
    echo json_encode(array("errors" => $errors, "success" => $success));
}
