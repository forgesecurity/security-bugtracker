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

class type_addserver
{
	public $id_folder_servers;
	public $hostname;
	public $description;
	public $use;
	public $ipsaddress;
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

$fp1 = fopen("servers_hostnames.txt", "r");
$fp2 = fopen("servers_ips.txt", "r");
if ($fp1 && $fp2)
{
	while (!feof($fp1) && !feof($fp2))
	{
		$hostname = rtrim(fgets($fp1));
		$ips = str_replace($CONF_FILE_IP_SEPARATOR, $CONF_WEBISSUES_IP_SEPARATOR, rtrim(fgets($fp2)));

		$addserver = new type_addserver();
		$addserver->id_folder_servers = (int) $CONF_WEBISSUES_FOLDER_SERVERS;
		$addserver->hostname = $hostname;
		$addserver->description = $hostname;
		$addserver->use = "Production";
		$addserver->ipsaddress = $ips;

		$param = new SoapParam($addserver, 'tns:type_addserver');
		$result = $clientsoap->__call('addserver', array('type_addserver'=>$param));
	}

	fclose($fp1);
	fclose($fp2);
}

$addscan = new type_addscan();
$addscan->id_folder_scans = $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_openvas_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_openvas_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "openvas";
$addscan->filter = "medium";

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

?>
