<?php
require_once "lib/engine.php";

$av = new MAV_Engine();

$av->setVerbose(false);
$av->listPUP(true);

$av->enableSignature(true);
$av->enableHeuristics(true);

$av->scan("/tmp");

?>
