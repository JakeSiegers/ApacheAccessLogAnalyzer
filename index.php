<?php
	new AccessLogParser();

	class AccessLogParser{

		function __construct(){
			$this->importantKeys = array(
				//"Linker"
				//,"Website"
			);

			$this->excludeKeys = array(
				"AccessLogParser"
				,"/inc/js/"
				,".png"
				,".ico"
				,".js"
				,".css"
				,".gif"
				,".jpg"
				,".svg"
				//,".php" //Maybe a bad idea
			);


			$this->supportedRequestTypes = array(
				 'GET'
				,'POST'
				,'OPTIONS'
				,'PROPFIND'
				,'HEAD'
			);

			$log = file_get_contents("C:\Server\Programs\Apache24\logs\access.log");
			$logArray = explode("\r\n",$log);
			$logArray  = array_reverse($logArray);

		 	$this->results = array();
		 	$this->accessTotal = 0;
			foreach($logArray as $logEntry){
				if($logEntry == ""){
					continue;
				}
				$date = $this->alp_getDate($logEntry);
				$url = $this->alp_getUrl($logEntry);
				$statusCode = $this->apl_getStatusCode($logEntry);
				if($this->alp_checkImportant($url)  && $statusCode == "200" && !$this->alp_alreadyLogged($url)){
					$this->results[] = array(
						'date' => date('Y-m-d, g:i a',$date)
						,'url' => $url
						,'code' => $statusCode
					);
					$this->accessTotal++;
				}
			}
			$this->alp_head();
			$this->alp_generateTable($this->results);
			$this->alp_foot();
		}

		function alp_alreadyLogged($url){
			foreach($this->results as $result){
				if(strtolower($result['url']) == strtolower($url)){
					return true;
				}
			}
			return false;
		}

		function alp_head(){
			?>
			<!DOCTYPE html>
			<html>
			<head>
				<style>
					body{
						padding:10px;
						margin:0px;
					}
					table{
						border-collapse: collapse;
						border:solid 1px black;
					}
					td{
						min-width: 200px;
					}
					tr,td,th{
						padding:5px;
						text-align:left;
						border:solid 1px black;
					}
					pre{
						border:dashed 1px red;
					}
				</style>
			</head>
			<body>

			<?php
		}

		function alp_foot(){
			?>
			</body>
			</html>
			<?php
		}

		function alp_generateTable($results){
			echo '<h1>Access Log</h1>';
			echo 'Duplicates Ignored, All Url Parameters Removed. Last Slash Removed, Only code 200';
			echo '<h3>Total Hits: '.$this->accessTotal.'</h3>';
			if(count($this->importantKeys)>0){
				echo '<br />Have The Following Keywords:';
				echo '<pre>';
				print_r($this->importantKeys);
				echo '</pre>';
			}
			echo '<br /><b>DO NOT</b> Have The Following Keywords:';
			echo '<pre>';
			print_r($this->excludeKeys);
			echo '</pre>';
			echo '<table>';
			echo '<tr><th>Most Recent Access Date</th><th>Code</th><th>URL</th></tr>';
			foreach($results as $r){
				echo '<tr><td>'.$r['date'].'</td><td>'.$r['code'].'</td><td>'.$r['url'].'</td></tr>';
			}
			echo '</table>';
		}

		function alp_getDate($entry){
			if(FALSE === $result = $this->alp_getRegexMatch('/(?<=\[)(.*)(?=\])/',$entry)){
				die("Could not find date in '".$entry."'");
			}
			return strtotime($result);
		}

		function apl_getStatusCode($entry){
			if(FALSE === $result = $this->alp_getRegexMatch('/(?<=HTTP\/\d\.\d" )\d{3}(?=(.*)$)/',$entry)){
				die ("Could not find status in '".$entry."'");
			}
			return $result;
		}

		function alp_getUrl($entry){
			//We have to splt up the regex because php doesn't allow variable lookbehinds (ie, ?<=\"(POST|GET)) will not work because of the variable length.
			$tries = array();
			foreach($this->supportedRequestTypes as $requestType){
				$tries[] = '/(?<=\"'.$requestType.' )(.*)(?= HTTP(.*)$)/';
 			}

			$found = false;
			foreach($tries as $try){
				$result = $this->alp_getRegexMatch($try,$entry);
				if($result !== FALSE){
					break;
				}
			}
			if($result === FALSE){
				die("Could not find URL in '".$entry."'");
			}
			//If there's parameters at the end of the url, ie ?, we cut them off.
			//Also cut off end slash if it exists
			$url = explode("?", $result, 2);
			if(substr($url[0], -1) == "/"){
				return substr($url[0], 0, -1);
			}else{
				return $url[0];
			}
		}

		function alp_checkImportant($url){
			//we want these!
			if(count($this->importantKeys) != 0){
				$passInclude = false;
				foreach($this->importantKeys as $key){
					if(FALSE !== strstr(strtolower($url),strtolower($key))){
						$passInclude = true;
						break;
					}
				}
			}else{
				$passInclude = true;
			}

			//We don't want these
			$passExclude = true;
			foreach($this->excludeKeys as $key){
				if(FALSE !== strstr(strtolower($url),strtolower($key))){
					$passExclude = false;
					break;
				}
			}
			return $passInclude && $passExclude;
		}

		//returns first match, or false if it doesn't exist.
		function alp_getRegexMatch($regex,$input){
			$matches = array();
			if(FALSE === preg_match($regex,$input,$matches)){
				die("Failed to regex: '".$regex."' => '".$input."'");
			}
			if(!isset($matches[0])){
				return false;
			}
			return $matches[0];
		}
	}
?>