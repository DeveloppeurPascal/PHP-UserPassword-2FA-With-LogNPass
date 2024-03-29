<?php
	// PHP User Password Basics
	// (c) Patrick Prémartin
	//
	// Distributed under license AGPL.
	//
	// Infos and updates :
	// https://github.com/DeveloppeurPascal/PHP-UserPassword-Basics

	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// !!! NEVER CHANGE THIS FILE ON YOUR SITES !!!
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	
	// This file contains the default settings of the software.
	// It will be overwritten each time the code repository is 
	// updated when there are changes in default values or new 
	// settings. Never modify it directly.
	//
	// For localhost server, copy your defines in a protected/config-dev.inc.php file.
	//
	// For real domaine or IP, copy your defines in a protected/config-release.inc.php file.
	
	// database server name or IP (localhost or other)
	if (!defined("DB_HOST"))
		define("DB_HOST", "");

	// database name
	if (!defined("DB_NAME"))
		define("DB_NAME", "");

	// database user name
	if (!defined("DB_USER"))
		define("DB_USER", "");

	// database user password
	if (!defined("DB_PASS"))
		define("DB_PASS", "");

	// debug mode
	if (!defined("_DEBUG"))
		define("_DEBUG", false);

	// global password salt (put something in it in your config-dev.inc.php or config-release.inc.php)
	if (!defined("PWD_SALT"))
		define("PWD_SALT", "");

	// relative or global url of connected user home page
	// (by default it is the same as for non connected user)
	if (!defined("URL_CONNECTED_USER_HOMEPAGE"))
		define("URL_CONNECTED_USER_HOMEPAGE", "./");

	// absolute link to your website (don't forget a "/" at the end)
	// (exemple : "https://mywebsite.com/")
	if (!defined("SITE_URL"))
		define("SITE_URL","");

	// salt for signup activation key (in email link)
	if (!defined("SIGNUP_SALT"))
		define("SIGNUP_SALT", "");

	// salt for lost password confirmation key (in email link)
	if (!defined("LOSTPASSWORD_LINK_SALT"))
		define("LOSTPASSWORD_LINK_SALT", "");

	// salt for lost password change key (in the change password form)
	if (!defined("LOSTPASSWORD_FORM_SALT"))
		define("LOSTPASSWORD_FORM_SALT", "");
