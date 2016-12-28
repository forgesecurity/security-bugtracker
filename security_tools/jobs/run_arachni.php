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

include( 'common.php' ); 

$CONF_COOKIES_TEST = "";

$credentials = array('login' => $CONF_WEBISSUES_ARACHNI_LOGIN, 'password' => $CONF_WEBISSUES_ARACHNI_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

add_assets_urls();

$addscan = new type_addscan();
$addscan->id_folder_scans = (int) $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_".rand()."_arachni_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_".rand()."_arachni_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "arachni";
$addscan->filter = "medium"; 

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

if($result)
{
	$id_scan = $result->result_addscan_details->id_scan;

	$geturls = new type_geturls();
	$geturls->id_folder_web = $CONF_WEBISSUES_FOLDER_WEB;
	$param = new SoapParam($geturls, 'tns:type_geturls');
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

			$cmd = "$CONF_ARACHNI_BIN $url --http-cookie-string=\"".$CONF_COOKIES_TEST."\" --http-cookie-string=\"".$CONF_COOKIES_TEST."\" --report-save-path /tmp/arachni.afr";
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

								if($threat >= $GLOBAL_SEVERITY)
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
