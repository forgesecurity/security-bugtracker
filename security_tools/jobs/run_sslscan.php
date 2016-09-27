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

include( 'run_sslscan.conf.php' ); 

ini_set('default_socket_timeout', 600);
ini_set('soap.wsdl_cache_enabled', 0);
	
class type_addurl
{
  public $id_folder_web;
  public $name;
  public $description;
  public $url;
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
	
class type_geturls
{
  public $id_folder_web;
}
	/*
$credentials = array('login' => $CONF_WEBISSUES_SSLSCAN_LOGIN, 'password' => $CONF_WEBISSUES_SSLSCAN_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

$addurl = new type_addurl();

$fp1 = fopen("web_names.txt", "r");
$fp2 = fopen("web_urls.txt", "r");
if ($fp1 && $fp2)
{
  while (!feof($fp1) && !feof($fp2))
  {
    $name = fgets($fp1);
    $url = fgets($fp2);

    $addurl->id_folder_web = $CONF_WEBISSUES_FOLDER_WEB;
    $addurl->name = $name;
    $addurl->description = $name;
    $addurl->url = $url;
		  
    if(!empty($url))
    { 
      $param = new SoapParam($addurl, 'tns:type_addurl');
      $result = $clientsoap->__call('addurl', array('type_addurl'=>$param));
    }
  }
}

fclose($fp1);
fclose($fp2);

$addscan = new type_addscan();
$addscan->id_folder_scans = (int) $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_sslscan_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_sslscan__".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "sslscan";
$addscan->filter = "medium"; // $severity = 2;*/
$severity = 2;
/*
$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

if($result)
{
  $id_scan = $result->result_addscan_details->id_scan;

  $geturls = new type_geturls();
  $geturls->id_folder_web = $CONF_WEBISSUES_FOLDER_WEB;
  $param = new SoapParam($addurl, 'tns:type_geturls');
  $results = $clientsoap->__call('geturls', array('type_geturls'=>$param));
	  
  if($results)
  {
    if(isset($results->result_geturls_details) && count($results->result_geturls_details) > 1)
	$results = $results->result_geturls_details;
    
    foreach($results as $resulturl)
    {
      $id_url = $resulturl->id_url;
      $name = $resulturl->name;
      $url = $resulturl->url;
      $url = chop($url);
      */
      //$outputjson = "$CONF_SSLSCAN_BIN $url";
      $outputjson = file_get_contents("test.json");
	  
      if(!empty($outputjson))
      {
	$parsed_json = json_decode($outputjson);
	
	if(isset($parsed_json[0]->{'host'}))
	{
	  if(isset($parsed_json[0]->{'endpoints'}[0]))
	  {
	    if(isset($parsed_json[0]->{'endpoints'}[0]->{'details'}->{'vulnBeast'}))
	    {
	      if($parsed_json[0]->{'endpoints'}[0]->{'details'}->{'vulnBeast'})
	      {
		// severity function of CVSS
		// CVE-2011-3389
		$threat = 3; //high	    
		if($threat >= $severity)
		{
		/*
		  $addissue = new type_addissue();
		  $addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
		  $addissue->name = "Beast Vulnerability"; // CVE COMMON NAME
		  $addissue->description = "Beast Vulnerability\n\n".$parsed_json[0]->{'host'};
		  $addissue->assigned = "";
		  $addissue->state = "Actif";
		  $addissue->severity = $threat;
				      
		  $param = new SoapParam($addissue, 'tns:addissue');
		  $result = $clientsoap->__call('addissue',array('addissue'=>$param));
		  */
		  
		  echo "Beast Vulnerability 3";
		}
	      }
	    }
	  }
	}
      }
      /*
    }

    $finishscan = new type_finishscan();
    $finishscan->id_scan = $id_scan;
		  
    $param = new SoapParam($finishscan, 'tns:finishscan');
    $result = $clientsoap->__call('finishscan',array('finishscan'=>$param));
  }
}*/

?>
