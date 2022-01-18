<?php
		if(empty($_GET["url"])) exit(1);
		$url = $_GET["url"];
		$parsed= parse_url($url);
		echo 'Response:<br>';
		if ($parsed[host] === 'passparser.web.ctf.shellmates.club'){
			$curl_handle=curl_init();
			curl_setopt($curl_handle, CURLOPT_SSL_VERIFYPEER, false);
			curl_setopt($curl_handle, CURLOPT_SSL_VERIFYHOST, false);
			curl_setopt($curl_handle, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($curl_handle,CURLOPT_URL,$url);
			$buffer = curl_exec($curl_handle);
			curl_close($curl_handle);
			print($buffer);
			echo htmlspecialchars($buffer, ENT_QUOTES);
			
		} else{
			die("You don't have permesion");
		}
?>