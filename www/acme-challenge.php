<?php
//Config file to read
$conf = '/etc/acmepl/config';

//Unable to show key.thumbprint couple
if (
	//Handle config parsing
	!is_readable($conf) || ($config = file_get_contents($conf)) === false || ($config = json_decode($config)) === null ||
	//Handle thumbprint file read
	!is_readable($config->thumbprint) || ($thumbprint = file_get_contents($config->thumbprint)) === false ||
	//Handle get key parsing
	empty($_GET['key']) || !preg_match('/^[-_a-zA-Z0-9]+$/', $_GET['key'])
) {
	header((!empty($_SERVER['SERVER_PROTOCOL'])?$_SERVER['SERVER_PROTOCOL']:'HTTP/1.0').' 404 Not Found');
	exit;
}

//Send plain text header
header('Content-Type: text/plain');

//Display key.thumbprint couple
echo $_GET['key'].$thumbprint;
