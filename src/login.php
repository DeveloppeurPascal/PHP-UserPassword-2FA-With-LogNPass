<?php
	// PHP User Password Basics
	// (c) Patrick Prémartin
	//
	// Distributed under license AGPL.
	//
	// Infos and updates :
	// https://github.com/DeveloppeurPascal/PHP-UserPassword-Basics
	
	session_start();
	require_once(__DIR__."/inc/functions.inc.php");
	require_once(__DIR__."/inc/config.inc.php");

	// This page is only available when no user is connected.
	if (hasCurrentUser()) {
		header("location: index.php");
		exit;
	}

	define("CLoginForm", 1);
	define("CLogNPassForm", 2);

	$LoginStatus = CLoginForm;
	
	$error = false;
	$error_message = "";
	$DefaultField = "User";

	if (isset($_POST["frm"]) && ("1" == $_POST["frm"])) {
		$email = isset($_POST["user"])?trim(strip_tags($_POST["user"])):"";
		if (empty($email)) {
			$error = true;
			$error_message .= "Fill your user email address to connect.\n";
		}
		else {
			$password = isset($_POST["password"])?trim(strip_tags($_POST["password"])):"";
			if (empty($password)) {
				$error = true;
				$error_message .= "Fill your password to connect.\n";
				$DefaultField = "Password";
			}
			else {
				$db = getPDOConnection();
				if (! is_object($db)) {
					$error = true;
					$error_message .= "Database access error. Contact the administrator.\n";
				}
				else {
					$qry = $db->prepare("select id, password, pwd_salt, enabled, comp from users where email=:email limit 0,1");
					$qry->execute(array(":email" => $email));
					if (false === ($rec = $qry->fetch(PDO::FETCH_OBJ))) {
						$error = true;
						$error_message .= "Unknown user.\n";
					}
					else if (1 != $rec->enabled) {
						$error = true;
						$error_message .= "Access denied.\n";
					}
					else if (getEncryptedPassword($password, $rec->pwd_salt) != $rec->password) {
						$error = true;
						$error_message .= "Access denied.\n";
					}
					else {
						$lnp_phrase = getUserCompValue($rec->comp, "lognpass_phrase");
						if ((false !== $lnp_phrase) && (! empty($lnp_phrase))) {
							$_SESSION["temp_id"] = $rec->id;
							$_SESSION["temp_email"] = $email;
							$LoginStatus = CLogNPassForm;
							$DefaultField = "LNPCode";
						}
						else {
							setCurrentUserId($rec->id);
							setCurrentUserEmail($email);
							header("location: ".URL_CONNECTED_USER_HOMEPAGE);
							exit;
						}
					}
				}
			}
		}
	}
	else if (isset($_POST["frm"]) && ("2" == $_POST["frm"])) {
		$LoginStatus = CLogNPassForm;
		$DefaultField = "LNPCode";
		$code = isset($_POST["code"])?trim(strip_tags($_POST["code"])):"";
		if (empty($code)) {
			$error = true;
			$error_message .= "Fill the Log'n Pass code.\n";
		}
		else if (isset($_SESSION["temp_id"]) && isset($_SESSION["temp_email"])) {
			$id = $_SESSION["temp_id"];
			if (! is_int($id)) {
				$error = true;
				$error_message .= "Access denied.\n";
				$LoginStatus = CLoginForm;
			}

			$email = $_SESSION["temp_email"] ;
			if (empty($email)) {
				$error = true;
				$error_message .= "Access denied.\n";
				$LoginStatus = CLoginForm;
			}

			if (! $error) {
				$db = getPDOConnection();
				if (! is_object($db)) {
					$error = true;
					$error_message .= "Database access error. Contact the administrator.\n";
					$LoginStatus = CLoginForm;
				}
				else {
					$qry = $db->prepare("select enabled, comp from users where id=:id and email=:email");
					$qry->execute(array(":id" => $id, ":email"=>$email));
					if (false === ($rec = $qry->fetch(PDO::FETCH_OBJ))) {
						$error = true;
						$error_message .= "Unknown user.\n";
					}
					else if (1 != $rec->enabled) {
						$error = true;
						$error_message .= "Access denied.\n";
					}
					else {
						require_once(__DIR__."/inc/lognpass-inc.php");
						$lnp_phrase = getUserCompValue($rec->comp, "lognpass_phrase");
						if ((false !== $lnp_phrase) && (! empty($lnp_phrase)) && (true === lognpass_check_password($lnp_phrase, $code))) {
							unset($_SESSION["temp_id"]);
							unset($_SESSION["temp_email"]);
							setCurrentUserId($id);
							setCurrentUserEmail($email);
							header("location: ".URL_CONNECTED_USER_HOMEPAGE);
							exit;
						}
						else {
							$error = true;
							$error_message .= "Wrong code for this secret pass phrase. (check if the code has expired and retry ou verify the phrase)\n";
							$DefaultField = "LNPCode";
						}
					}
				}
			}
		}
		else {
			$error = true;
			$error_message .= "Access denied.\n";
			$LoginStatus = CLoginForm;
		}
	}

?><!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="content-type" content="text/html; charset=UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=yes">
		<title>Log in - PHP User Password Basics</title>
		<style>
			.error {
				color: red;
				background-color: yellow;
			}
		</style>
	</head>
	<body><?php include_once(__DIR__."/inc/header.inc.php"); ?>
		<h2>Log in</h2><?php
	if ($error && (! empty($error_message))) {
		print("<p class=\"error\">".nl2br($error_message)."</p>");
	}

	switch ($LoginStatus) {
		case CLoginForm:
?><form method="POST" action="login.php" onSubmit="return ValidForm();"><input type="hidden" name="frm" value="1">
			<p>
				<label for="User">User email</label><br>
				<input id="User" name="user" type="email" value="<?php print(isset($email)?htmlspecialchars($email):""); ?>" prompt="Your email address">
			</p>
			<p>
				<label for="Password">Password</label><br>
				<input id="Password" name="password" type="password" value="" prompt="Your password">
			</p>
			<p>
				<button type="submit">Connect</button>
			</p>
		</form>
<script>
	document.getElementById('<?php print($DefaultField); ?>').focus();
	function ValidForm() {
		email = document.getElementById('User');
		if (0 == email.value.length) {
			email.focus();
			window.alert('Your email address is needed !');
			return false;
		}
		pwd = document.getElementById('Password');
		if (0 == pwd.value.length) {
			pwd.focus();
			window.alert('New password needed !');
			return false;
		}
		return true;
	}
</script>
		<p><a href="lostpassword.php">Lost password</a></p>
		<p><a href="signup.php">Sign up</a></p>
<?php
			break;
		case CLogNPassForm:
?><form method="POST" action="login.php" onSubmit="return ValidForm();"><input type="hidden" name="frm" value="2">
			<p>
				<label for="LNPCode">Log'n Pass code</label><br>
				<input id="LNPCode" name="code" type="text" value="" prompt="Log'n Pass code">
			</p>
			<p>
				<button type="submit">Connect</button>
			</p>
		</form>
<script>
	document.getElementById('<?php print($DefaultField); ?>').focus();
	function ValidForm() {
		code = document.getElementById('LNPCode');
		if (0 == code.value.length) {
			code.focus();
			window.alert('Log\'n Pass code needed !');
			return false;
		}
		return true;
	}
</script>
<?php
			break;
	}
	include_once(__DIR__."/inc/footer.inc.php"); ?></body>
</html>