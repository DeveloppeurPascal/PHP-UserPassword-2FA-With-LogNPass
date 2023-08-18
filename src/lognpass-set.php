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

	// This page is only available when a user is connected.
	if (! hasCurrentUser()) {
		header("location: index.php");
		exit;
	}

	define("CLogNPassForm", 1);
	define("CLogNPassOk", 2);
	
	$LogNPassStatus = CLogNPassForm;

	$error = false;
	$error_message = "";
	$DefaultField = "LNPPhrase";

	if (isset($_POST["frm"]) && ("1" == $_POST["frm"])) {
		$phrase = isset($_POST["phrase"])?trim(strip_tags($_POST["phrase"])):"";
		if (empty($phrase)) {
			$error = true;
			$error_message .= "Fill your secret pass phrase.\n";
			$DefaultField = "LNPPhrase";
		}
		else {
			$code = isset($_POST["code"])?trim(strip_tags($_POST["code"])):"";
			if (empty($code)) {
				$error = true;
				$error_message .= "Fill the Log'n Pass code.\n";
				$DefaultField = "LNPCode";
			}
			else {
				require_once(__DIR__."/inc/lognpass-inc.php");
				lognpass_set_temp_dir(__DIR__."/temp");
				$phrase_md5 = md5($phrase);
				if (true !== lognpass_check_password($phrase_md5, $code)) {
					$error = true;
					$error_message .= "Wrong code for this secret pass phrase. (check if the code has expired and retry ou verify the phrase)\n";
					$DefaultField = "LNPCode";
				}
				else {
					$db = getPDOConnection();
					if (! is_object($db)) {
						$error = true;
						$error_message .= "Database access error. Contact the administrator.\n";
					}
					else {
						$qry = $db->prepare("select enabled, comp from users where id=:id");
						$qry->execute(array(":id" => getCurrentUserId()));
						if (false === ($rec = $qry->fetch(PDO::FETCH_OBJ))) {
							$error = true;
							$error_message .= "Unknown user.\n";
						}
						else if (1 != $rec->enabled) {
							$error = true;
							$error_message .= "Access denied.\n";
						}
						else {
							setUserCompValue($rec->comp, "lognpass_phrase", $phrase_md5);
							$qry = $db->prepare("update users set comp=:comp where id=:id");
							$qry->execute(array(":comp" => $rec->comp, ":id" => getCurrentUserId()));
							$LogNPassStatus = CLogNPassOk;
						}
					}
				}
			}
		}
	}
?><!DOCTYPE html>
<html lang="en">
	<head>
		<meta charset="UTF-8">
		<meta http-equiv="content-type" content="text/html; charset=UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=yes">
		<title>Change Log'n Pass secret phrase - PHP User Password Basics</title>
		<style>
			.error {
				color: red;
				background-color: yellow;
			}
		</style>
	</head>
	<body><?php include_once(__DIR__."/inc/header.inc.php"); ?>
		<h2>Change Log'n Pass secret phrase</h2><?php
	if ($error && (! empty($error_message))) {
		print("<p class=\"error\">".nl2br($error_message)."</p>");
	}

	switch ($LogNPassStatus) {
		case CLogNPassForm:
?><form method="POST" action="lognpass-set.php" onSubmit="return ValidForm();"><input type="hidden" name="frm" value="1">
	<p>
		<label for="LNPPhrase">Secret phrase</label><br>
		<input id="LNPPhrase" name="phrase" type="text" value="<?php print(isset($phrase)?htmlspecialchars($phrase):""); ?>" prompt="Your secret phrase (the same than in Log'n Pass app)">
	</p>
	<p>
		<label for="LNPCode">Log'n Pass code</label><br>
		<input id="LNPCode" name="code" type="text" value="" prompt="Log'n Pass code">
	</p>
	<p>
		<button type="submit">Activate Log'n Pass on my account</button>
	</p>
</form><script>
	document.getElementById('<?php print($DefaultField); ?>').focus();
	function ValidForm() {
		phrase = document.getElementById('LNPPhrase');
		if (0 == phrase.value.length) {
			phrase.focus();
			window.alert('A secret phrase is needed !');
			return false;
		}
		code = document.getElementById('LNPCode');
		if (0 == code.value.length) {
			code.focus();
			window.alert('Log\'n Pass code needed !');
			return false;
		}
		return true;
	}
</script><?php
			break;
		case CLogNPassOk:
?><p>Log'n Pass is activated on your account. Don't forget your pass phrase or your account will be blocked.</p><?php
			break;
		default :
	}
	include_once(__DIR__."/inc/footer.inc.php"); ?></body>
</html>