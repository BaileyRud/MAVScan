#!/usr/bin/php
<?php
require_once "../lib/engine.php";
$av_cli_version = 1.0;
$av = new MAV_Engine();

# options

$shortopts = "";
$shortopts .= "h"; # show help
$shortopts .= "v"; # verbose mode

$longopts = array(
	"help", # show help
	"enable-heuristics::", # enable heuristical scanning
	"enable-signature::", # enable signature-based scanning
	"show-pup", # show/hide potential unwanted programs (PUPs)
	"update", # update local virus-databases
);

$options = getopt($shortopts, $longopts);
$dir = end($argv);
$no_scan = false;

# enable verbose mode
$av->setVerbose(false);
if(isset($options['v']) && $options['v'] !== "false" || isset($options['verbose']) && $options['verbose'] !== "false"){
	$av->setVerbose(true);
}

# enable heuristical-based scan
$av->enableHeuristics(true);
if(isset($options['enable-heuristics']) && $options['enable-heuristics'] == "false"){
	$av->enableHeuristics(false);
}

# enable signature-based scan
$av->enableSignature(true);
if(isset($options['enable-signature']) && $options['enable-signature'] == "false"){
	$av->enableSignature(false);
}

# show/hide PUPs
$av->listPUP(true);
if(isset($options['show-pup'])){
	if($options['show-pup'] == false) $av->listPUP(false);
}

# update virus-database
if(isset($options['update']) && $options['update'] !== "false"){
	$no_scan = true;
	$update = $av->update();
	if($update !== false) echo "\nVirus-database updated successfully!\n\n";
	else echo "\nUnknown error - could not update Virus-database!\n\n";
} else{
	if($argc <= 1 || empty($dir) || substr($dir, 0, 1) == "-"){
		$display_help = "die";
	}
	if(!is_dir($dir) && !file_exists($dir)){
		$display_help = "die";
	}
}

# show help
if(isset($options['h']) && $options['h'] !== "false" || isset($options['help']) && $options['help'] !== "false" || isset($display_help)){
	echo "\n";
	echo "Mindrun AntiVirus (MAVscan) - Malware scanner for webhosting environments.\n";
	echo "Copyright (c) ".date("Y")." Mindrun Networks.\n";
	echo "\n";
	echo "Commands and Options:\n";
	echo "-h / --help		Print this information screen\n";
	echo "-v / --verbose		Be verbose, more detailed output\n";
	echo "--enable-heuristics	Enable heuristical scanning (default: true)\n";
	echo "--enable-signature	Enable signature-based scanning (default: true)\n";
	echo "--show-pup		Show/hide potential unwanted programs (PUP, default: true)\n";
	echo "--update		Updates the local virus-database\n";
	echo "\n";

	if(isset($display_help)) die();
}

if($no_scan !== false) die();
if(substr($dir,0,1) == "-"){
	echo "\nPlease specify a path to scan!\n\n";
} else{
	$av->scan($dir);
}

?>
