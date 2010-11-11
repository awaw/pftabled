<html>
<body>
<?
$server = '127.0.0.1';
$port = 12345;
$table = 'test';
$key = '';

if ($_POST["ip"]) {
	$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
	$msg  = pack('CCxC', 1, 1, 32);
	$msg .= inet_pton($_POST["ip"]);
	$msg .= pack('a32N', $table, time());
	$msg .= hash_hmac('sha1', $msg, $key, TRUE);
	socket_sendto($sock, $msg, strlen($msg), 0, $server, $port);
	socket_close($sock);
}
?>
<br/>
<center>
<form action="" method="post">
<input name="ip" />
<input type="submit" value="&nbsp;&nbsp;OK&nbsp;&nbsp;" />
</form>
</center>
</body>
</html>
