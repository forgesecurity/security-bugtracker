<?php
/**************************************************************************
* Security Plugin Copyright (C) 2015 Eric Therond
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
**************************************************************************/

include( 'run_dependencycheck.conf.php' ); 

ini_set('default_socket_timeout', 600);
ini_set('soap.wsdl_cache_enabled', 0);
	
class type_addcode
{
  public $id_folder_codes;
  public $name;
  public $description;
  public $code;
}
	
class type_addscan
{
  public $id_folder_scans;
  public $name;
  public $description;
  public $tool;
  public $filter;
}
	
class type_finishscan
{
  public $id_scan;
}
	
class type_addissue
{
  public $id_folder_bugs;
  public $name;
  public $description;
  public $assigned;
  public $state;
  public $severity;
  public $version;
}
	
class type_getcodes
{
  public $id_folder_codes;
}
	
$credentials = array('login' => $CONF_WEBISSUES_DCHECK_LOGIN, 'password' => $CONF_WEBISSUES_DCHECK_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

$addcode = new type_addcode();

$fp1 = fopen("codes_names.txt", "r");
$fp2 = fopen("codes_paths.txt", "r");
if ($fp1 && $fp2)
{
  while (!feof($fp1) && !feof($fp2))
  {
    $name = fgets($fp1);
    $code = fgets($fp2);

    $addcode->id_folder_codes = $CONF_WEBISSUES_FOLDER_CODES;
    $addcode->name = $name;
    $addcode->description = $name;
    $addcode->code = $code;
		  
    if(!empty($code))
    { 
      $param = new SoapParam($addcode, 'tns:type_addcode');
      $result = $clientsoap->__call('addcode', array('type_addcode'=>$param));
    }
  }
}

fclose($fp1);
fclose($fp2);

$addscan = new type_addscan();
$addscan->id_folder_scans = (int) $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_dependency-check_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_dependency-check_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "dependency-check";
$addscan->filter = "medium"; // $severity = 2;
$severity = 2;

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

if($result)
{
  $id_scan = $result->result_addscan_details->id_scan;

  $getcodes = new type_getcodes();
  $getcodes->id_folder_codes = $CONF_WEBISSUES_FOLDER_CODES;
  $param = new SoapParam($addcode, 'tns:type_getcodes');
  $results = $clientsoap->__call('getcodes', array('type_getcodes'=>$param));
	  
  if($results)
  {
    if(isset($results->result_getcodes_details) && count($results->result_getcodes_details) > 1)
	$results = $results->result_getcodes_details;
    
    foreach($results as $resultcode)
    {
      $id_code = $resultcode->id_code;
      $name = $resultcode->name;
      $code = $resultcode->code;
      
      $out = shell_exec("$CONF_DEPENDENCYCHECK_BIN --app temp --format XML --scan $code --out $code/dependency-check-report.xml"); 
      $outputxml = file_get_contents("$code/dependency-check-report.xml");
      $out = shell_exec("rm $code/dependency-check-report.xml");
	  
      if(!empty($outputxml))
      {
	$report = new SimpleXMLElement($outputxml);
	if(isset($report->dependencies->dependency))
	{
	  foreach ($report->dependencies->dependency as $dependency) 
	  {
	    if(isset($dependency->fileName))
	    {
	      if(isset($dependency->vulnerabilities))
	      {
		$lastthreat = 0;
		$description = "";
		foreach($dependency->vulnerabilities->vulnerability as $vulnerability)
		{
		  switch($vulnerability->severity)
		  {
		    case 'Log':$threat = 1;break;
		    case 'Low':$threat = 1;break;
		    case 'Medium':$threat = 2;break;
		    case 'High':$threat = 3;break;
		    default:$threat = 1;break; 
		  }
				    
		  if($threat > $lastthreat)
		    $lastthreat = $threat;
				    
		  if($threat >= $severity)
		    $description = $vulnerability->name."\n".$vulnerability->description."\n\n";
		}
				    
		if($lastthreat >= $severity)
		{
		  $description = "vulnerable target : $code\n\n".$description;
		  $addissue = new type_addissue();
		  $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
		  $addissue->name = "known vulnerabilities in ".$dependency->fileName;
		  $addissue->description = $description;
		  $addissue->assigned = "";
		  $addissue->state = "Actif";
		  $addissue->severity = $lastthreat;
				    
		  $param = new SoapParam($addissue, 'tns:addissue');
		  $result = $clientsoap->__call('addissue',array('addissue'=>$param));
		}
	      }
	    }
	  }
	}
      }
    }

    $finishscan = new type_finishscan();
    $finishscan->id_scan = $id_scan;
		  
    $param = new SoapParam($finishscan, 'tns:finishscan');
    $result = $clientsoap->__call('finishscan',array('finishscan'=>$param));
  }
}

?>
