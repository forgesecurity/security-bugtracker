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

include( 'run_openvas.conf.php' ); 

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

$credentials = array('login' => $CONF_WEBISSUES_OPENVAS_LOGIN, 'password' => $CONF_WEBISSUES_OPENVAS_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);
$addcode = new type_addcode();

$fp1 = fopen("codes_folders.txt", "r");
$fp2 = fopen("codes_names.txt", "r");
$fp3 = fopen("codes_paths.txt", "r");
if ($fp1 && $fp2 && $fp3)
{
	while (!feof($fp1) && !feof($fp2) && !feof($fp3))
	{
		$folder = fgets($fp1);
		$name = fgets($fp2);
		$code = fgets($fp3);

		$addcode->id_folder_codes = (int) $folder;
		$addcode->name = $name;
		$addcode->description = $name;
		$addcode->code = $code;

		$param = new SoapParam($addcode, 'tns:type_addcode');
		$result = $clientsoap->__call('addcode', array('type_addcode'=>$param));
	}

	fclose($fp1);
	fclose($fp2);
	fclose($fp3);
}

$addscan = new type_addscan();
$addscan->id_folder_scans = $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "dependencycheck";
$addscan->filter = "medium";

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

$outputxml = shell_exec ($CONF_DEPENDENCYCHECK_BIN);      

if(!empty($outputxml))
{
	$report = new SimpleXMLElement($outputxml);
	if(isset($report->report->results->result))
	{
		foreach ($report->report->results->result as $result) {
			if(isset($result->threat))
			{
				switch($result->threat)
				{
					case 'Log':$threat = 1;break;
					case 'Low':$threat = 1;break;
					case 'Medium':$threat = 2;break;
					case 'High':$threat = 3;break;
					default:$threat = 1;break; 
				}
			}

			if($threat >= $severity)
			{
				$addissue = new type_addissue();
				$addissue->id_folder_bugs = $id_folder_bugs;
				$addissue->name = $result->name;
				$addissue->description = $result->description;
				$addissue->assigned = "";
				$addissue->state = "Actif";
				$addissue->severity = $threat;

				$param = new SoapParam($addissue, 'tns:addissue');
				$result = $clientsoap->__call('addissue',array('addissue'=>$param));
			}
		}
	}
}

$finishscan = new type_finishscan();
$finishscan->id_scan = $alertscanid;

$param = new SoapParam($finishscan, 'tns:finishscan');
$result = $clientsoap->__call('finishscan',array('finishscan'=>$param));
}

?>
