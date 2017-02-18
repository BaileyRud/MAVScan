<?php

class MAV_Engine {

	private $_engine_version = 1.0;

	private $_summary;
	private $_verbose = false;
	private $_list_pup = true;
	
	private $_enableSignature = false;
	private $_enableHeuristics = false;
	
	/**
	 * Mindrun AV - Cloud Malware Protection
	 */
	private $_updateUrl;
	private $_updateKey;
	
	
	/**
	 * Constructor, currently nothing to perform
	 */
	public function __construct() {
		if(!file_exists(__DIR__."/../config.php")){
			die("Error: configuration-file (config.php) was not found!\n");
		} else{
			include_once __DIR__."/../config.php";
			if(defined('mav_sense_updateUrl')) $this->_updateUrl = mav_sense_updateUrl;
			if(defined('mav_sense_updateKey')) $this->_updateKey = mav_sense_updateKey;
		}
	}
	
	
	/**
	 * Switch on the verbose mode, more detailed output
	 *
	 * @param boolean $verbose The verbose mode (true|false)
	 */
	public function setVerbose($verbose) {
		if($verbose !== false){
			$this->_verbose = true;
		} else{
			$this->_verbose = false;
		}
	}
	
	
	/**
	 * Output PUPs (potential unwanted programs) with disabled verbose-mode (default: true)
	 *
	 * @param boolean $pup
	 */
	public function listPUP($pup) {
		if($pup !== false){
			$this->_list_pup = true;
		} else{
			$this->_list_pup = false;
		}
	}
	
	
	/**
	 * Enable the signature-based scanning (default: true)
	 *
	 * @param boolean $sign
	 */
	public function enableSignature($sign) {
		if($sign !== false){
			$this->_enableSignature = true;
		} else{
			$this->_enableSignature = false;
		}
	}
	
	
	/**
	 * Enable the heuristical-based scanning (default: true)
	 *
	 * @param boolean $heur
	 */
	public function enableHeuristics($heur) {
		if($heur !== false){
			$this->_enableHeuristics = true;
		} else{
			$this->_enableHeuristics = false;
		}
	}
	
	
	/**
	 * Update the virus signatures by the Mindrun Sense-AV-Cloud
	 */
	public function update() {
		# check for new updates
		$url = str_replace("/\/", "/", $this->_updateUrl."/sense/update.php?key=".$this->_updateKey."&sig=generic-info");
		$req = file_get_contents($url);
		if((int) substr(@$req, 0, 1) > 0) return false;
		
		$update = true;
		$vhash = sha1($req);
		if(file_exists(__DIR__."/db/vhash.txt")){
			$vhash_ex = file_get_contents(__DIR__."/db/vhash.txt");
			if($vhash == $vhash_ex){
				$update = false;
				if($this->_verbose !== false) echo "No update required.\n";
			} else{
				$update = true;
			}
		} else{
			file_put_contents(__DIR__."/db/vhash.txt", $vhash);
			$update = true;
		}
		
		# install updates
		if($update !== false || !file_exists(__DIR__."/db/generic.vdb")){
			$url = str_replace("/\/", "/", $this->_updateUrl."/sense/update.php?key=".$this->_updateKey."&sig=generic");
			$req = file_get_contents($url);
			
			file_put_contents(__DIR__."/db/generic.vdb", $req);
			return true;
		}
	}
	
	
	/**
	 * Scans a file or directory
	 *
	 * @param string $location The file or directory to scan
	 */
	public function scan($location) {
		echo "\nVirus-Scan started.\n";
		if(is_dir($location)) echo "Path: ".$location."\n\n";
		else echo "File: ".$location."\n\n";
		
		$this->_location_rp = realpath($location);
		$this->_summary = array(
			'count_files' => 0,
			'count_threads' => 0,
			'count_pup' => 0,
			'time' => 0
		);
		$time_start = microtime(true);
		
		# perform scan
		$scan = $this->rscan_dir($location);
		
		$time_end = microtime(true);
		$this->_summary['time'] = round($time_end - $time_start, 5);
		
		echo "\n- - Summary\n";
		echo "Files scanned:	".$this->_summary['count_files']."\n";
		echo "Threads found:	".$this->_summary['count_threads'].($this->_summary['count_pup'] > 0 ? "  (".$this->_summary['count_pup']." Potential Unwanted Programs)" : "")."\n";
		echo "Time:		".$this->_summary['time']."\n";
		echo "\n";
	}
	
	
	
	/**
	 * private functions including main AV-engine
	 */
	
	
	
	/**
	 * Recursively scans a directory and checks files based on the private scanning-functions.
	 *
	 * @param string $location The file/directory to scan
	 */
	private function rscan_dir ($location) {
		$files = array();
		$location_real = realpath($location);
		if(is_dir($location_real)){
			$scandir = scandir($location_real);
			foreach($scandir as $file){
				if($file !== "." && $file !== ".."){
					$file_real = str_replace("//", "/", $location."/".$file);
					$file_real = realpath($file_real);
					$file_relative = str_replace($this->_location_rp, "", $file_real);
					if(substr($file_relative,0,1)=="/") $file_relative = substr($file_relative, 1);
					
					if(is_dir($file_real)){
						# directory, scan resursively
						$this->rscan_dir($file_real);
					} else if(file_exists($file_real)){
						# file, scan
						$scan_sign = false;
						$scan_heur = false;
						if($this->_enableSignature !== false) $scan_sign = @$this->check_file_signature($file_real);
						if($this->_enableHeuristics !== false && $scan_sign == false) $scan_heur = @$this->check_file_heuristics($file_real);
						
						if($scan_sign == false && $scan_heur == false){
							if($this->_verbose !== false) echo "[OK]	$file_relative\n";
						} else if($scan_sign !== false && $scan_heur == false){
							$this->_summary['count_threads']++;
							echo "[FOUND]	$file_relative  (".$scan_sign['name'].")\n";
						} else if($scan_sign == false && $scan_heur !== false){
							if(isset($scan_heur['pup']) && $scan_heur['pup'] !== false){
								$this->_summary['count_pup']++;
								if($this->_verbose !== false || $this->_list_pup !== false) echo "[PUP]	$file_relative  (".$scan_heur['name'].")\n";
							} else{
								$this->_summary['count_threads']++;
								echo "[FOUND]	$file_relative  (".$scan_heur['name'].")\n";
							}
						} else if($scan_sign !== false && $scan_heur !== false){
							$this->_summary['count_threads']++;
							echo "[FOUND]	$file_relative  (".$scan_sign['name'].")\n";
						}
						
						$this->_summary['count_files']++;
					}
				}
			}
		} else if(file_exists($location_real)){
			$file_real = str_replace("//", "/", $location);
			$file_real = realpath($file_real);
			$file_relative = end(explode("/", $file_real));
			
			# file, scan
			$scan_sign = false;
			$scan_heur = false;
			if($this->_enableSignature !== false) $scan_sign = @$this->check_file_signature($file_real);
			if($this->_enableHeuristics !== false && $scan_sign == false) $scan_heur = @$this->check_file_heuristics($file_real);
						
			if($scan_sign == false && $scan_heur == false){
				if($this->_verbose !== false) echo "[OK]	$file_relative\n";
			} else if($scan_sign !== false && $scan_heur == false){
				$this->_summary['count_threads']++;
				echo "[FOUND]	$file_relative  (".$scan_sign['name'].")\n";
			} else if($scan_sign == false && $scan_heur !== false){
				if(isset($scan_heur['pup']) && $scan_heur['pup'] !== false){
					$this->_summary['count_pup']++;
					if($this->_verbose !== false || $this->_list_pup !== false) echo "[PUP]	$file_relative  (".$scan_heur['name'].")\n";
				} else{
					$this->_summary['count_threads']++;
					echo "[FOUND]	$file_relative  (".$scan_heur['name'].")\n";
				}
			} else if($scan_sign !== false && $scan_heur !== false){
				$this->_summary['count_threads']++;
				echo "[FOUND]	$file_relative  (".$scan_sign['name'].")\n";
			}
			
			$this->_summary['count_files']++;
		}
	}
	
	
	#private function 
	
	
	/**
	 * Checks a file based on virus signatures.
	 *
	 * @param string $file The relative file-path to check
	 */
	private function check_file_signature ($file) {
		# update if no signatures exists
		if(!file_exists(__DIR__."/db/generic.vdb")) $this->update();
		
		# decode signature
		$generic_vdb = file_get_contents(__DIR__."/db/generic.vdb");
		$generic_vdb_exp = explode("//", $generic_vdb);
		$generic_list = array();
		foreach($generic_vdb_exp as $vline){
			if(!empty($vline)){
				$vline = base64_decode(strrev($vline));
				$vline_exp = explode("|", $vline);
				$generic_list[] = array('sha1' => $vline_exp[0], 'name' => $vline_exp[1]);
			}
		}
		
		# scan file
		$virus = false;
		$file_real = realpath($file);
		$file_sha1 = sha1_file($file_real); # generate checksum
		
		foreach($generic_list as $generic_line){
			if($generic_line['sha1'] == $file_sha1){
				$virus = true;
				$virus_name = $generic_line['name'];
			}
		}
		
		return ($virus !== false ? array('sha1' => $file_sha1, 'name' => $virus_name) : false);
	}
	
	
	/**
	 * Checks a file based on heuristic analysis.
	 *
	 * @param string $file The absolute file-path to scan
	 */
	private function check_file_heuristics ($file) {
		$file_source = file_get_contents($file);
		$file_source_lines = explode("\n", $file_source);
		
		$pup_score = 0;
		$thr_score = 0;
		
		## Heuristics
		# CI, RCE
		
		if(strpos($file_source, "<?") !== false && preg_match("/eval\((base64|eval|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i", $file_source)){
			$thr_virus_score = 8.5;
			$thr_virus_name = "Heur.Trojan.CodeInjection";
		}
		
		if(strpos($file_source, "<?") !== false && count(explode("\n", $file_source)) <= 2 && stripos($file_source, "eval(") !== false){
			$thr_virus_score = 6;
			$thr_virus_name = "Heur.Trojan.CodeInjection";
		}
		
		# WebShell
		
		if(stripos($file_source, "system(") !== false || stripos($file_source, "shell(") !== false || stripos($file_source, "shell_exec(") !== false){
			$pup_virus_score = 4.7;
			$pup_virus_name = "Heur.PUP.WebShell";
		}
		
		if(strpos($file_source, "<?") !== false && preg_grep("/(system|shell_exec|shell)\([']?[\"]?(base64|killall|kill|\$_|\$\$|\$[A-Za-z_0-9\{]*(\(|\{|\[))/i", $file_source_lines)){
			$thr_virus_score = 8.7;
			$thr_virus_name = "Heur.Trojan.WebShell";
		}
		
		# Character frequency
		
		$chars_search = array("(", "+", "*");
		$chars_count = array();
		foreach($chars_search as $char){
			$chars_count[$char] = substr_count($file_source, $char);
		}
		foreach($chars_count as $char_k => $char_v){
			$freq = ($char_v / strlen($file_source) * 100);
			
			# PHP Crypto-Trojans
			if(strpos($file_source, "<?") !== false && strlen($file_source) >= 200){
				if($freq >= 32.5){
					$thr_virus_score = 5.5;
					$thr_virus_name = "Heur.Generic.CharFreq[".round($freq)."]";
				}
			}
		}
		
		## Evaluate the score
		
		if($pup_virus_score >= 3 && $thr_virus_score < 6){
			if(!isset($pup_virus_name)) $pup_virus_name = "Heur.PUP";
			$file_sha1 = sha1_file($file);
			
			return array('sha1' => $file_sha1, 'name' => $pup_virus_name, 'pup' => true);
		}
		else if($thr_virus_score >= 5.5){
			if(!isset($thr_virus_name)) $thr_virus_name = "Heur.Generic";
			$file_sha1 = sha1_file($file);
			
			return array('sha1' => $file_sha1, 'name' => $thr_virus_name);
		}
		else{
			return false;
		}
	}
	
	
}

?>
