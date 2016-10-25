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

include( 'run_arachni.conf.php' ); 

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

$credentials = array('login' => $CONF_WEBISSUES_ARACHNI_LOGIN, 'password' => $CONF_WEBISSUES_ARACHNI_PASSWORD);
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
$addscan->name = "scan_arachni_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_arachni__".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "arachni";
$addscan->filter = "medium"; // $severity = 2;
$severity = 2;

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

			//echo "url arachni 1 = '$url'\n";
			$url = chop($url);
			//echo "url arachni 2 = '$url'\n";

			$cmd = "$CONF_ARACHNI_BIN $url --http-request-header=\"audit=DECLARIS-MFLKZEMFLKZEMLFKZE-20160917\" --http-cookie-string=\"".$CONF_COOKIES_TEST."\" --report-save-path /tmp/arachni.afr";
			echo "$cmd";
			$out = shell_exec("$cmd"); 
			$out = shell_exec("$CONF_ARACHNI_REPORT_BIN /tmp/arachni.afr --report=xml:outfile=/tmp/arachni.xml"); 
			$outputxml = file_get_contents("/tmp/arachni.xml");
			//$out = shell_exec("rm /tmp/arachni.afr");
			//$out = shell_exec("rm /tmp/arachni.xml");

			if(!empty($outputxml))
			{
				$report = new SimpleXMLElement($outputxml);
				if(isset($report->issues->issue))
				{
					foreach ($report->issues->issue as $issue) 
					{
						if(isset($issue->name))
						{
							if(isset($issue->severity))
							{
								$threat = 0;
								switch($issue->severity)
								{
									case 'informational':$threat = 1;break;
									case 'low':$threat = 1;break;
									case 'medium':$threat = 2;break;
									case 'high':$threat = 3;break;
									default:$threat = 1;break; 
								}

								if($threat >= $severity)
								{
									$addissue = new type_addissue();
									$addissue->id_folder_bugs = $CONF_WEBISSUES_FOLDER_BUGS;
									$addissue->name = $issue->name;
									$addissue->description = $issue->description."\n\n".$issue->vector->url;
									$addissue->assigned = "";
									$addissue->state = "Actif";
									$addissue->severity = $threat;

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
