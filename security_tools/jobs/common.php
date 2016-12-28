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

include( './dev/conf.php' ); 

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
	public $target;
	public $cve;
	public $cvss;
	public $severity;
	public $version;
}

class type_geturls
{
	public $id_folder_web;
}

class type_getcodes
{
	public $id_folder_codes;
}

class type_addcode
{
	public $id_folder_codes;
	public $name;
	public $description;
	public $code;
}

function add_assets_urls()
{
	$addurl = new type_addurl();

	$fp1 = fopen($GLOBALS["ASSETS_WEB_NAMES"], "r");
	$fp2 = fopen($GLOBALS["ASSETS_WEB_URLS"], "r");
	if ($fp1 && $fp2)
	{
		while (!feof($fp1) && !feof($fp2))
		{
			$name = fgets($fp1);
			$url = fgets($fp2);

			$addurl->id_folder_web = $GLOBALS["CONF_WEBISSUES_FOLDER_WEB"];
			$addurl->name = $name;
			$addurl->description = $name;
			$addurl->url = $url;

			if(!empty($url))
			{ 
				try 
				{
					$param = new SoapParam($addurl, 'tns:type_addurl');
					$result = $GLOBALS["clientsoap"]->__call('addurl', array('type_addurl'=>$param));
				}
				catch (SoapFault $e) 
				{
					echo $e->getMessage()."\n";
				} 
			}
		}
	}

	fclose($fp1);
	fclose($fp2);
}

function add_assets_codes()
{
	$addcode = new type_addcode();

	$fp1 = fopen($GLOBALS["ASSETS_CODES_NAMES"], "r");
	$fp2 = fopen($GLOBALS["ASSETS_CODES_PATHS"], "r");
	if ($fp1 && $fp2)
	{
		while (!feof($fp1) && !feof($fp2))
		{
			$name = fgets($fp1);
			$code = fgets($fp2);

			$addcode->id_folder_codes = $GLOBALS["CONF_WEBISSUES_FOLDER_CODES"];
			$addcode->name = $name;
			$addcode->description = $name;
			$addcode->code = $code;

			if(!empty($code))
			{ 
				try 
				{
					$param = new SoapParam($addcode, 'tns:type_addcode');
					$result = $GLOBALS["clientsoap"]->__call('addcode', array('type_addcode'=>$param));
				}
				catch (SoapFault $e) 
				{
					echo $e->getMessage()."\n";
				} 
			}
		}

		fclose($fp1);
		fclose($fp2);
	}
}

function add_assets_servers()
{
	$addserver = new type_addserver();

	$fp1 = fopen($GLOBALS["ASSETS_SERVERS_HOSTNAMES"], "r");
	$fp2 = fopen($GLOBALS["ASSETS_SERVERS_IPS"], "r");
	if ($fp1 && $fp2)
	{
		while (!feof($fp1) && !feof($fp2))
		{
			$hostname = rtrim(fgets($fp1));
			$ips = str_replace($GLOBALS["CONF_FILE_IP_SEPARATOR"], $GLOBALS["CONF_WEBISSUES_IP_SEPARATOR"], rtrim(fgets($fp2)));

			echo "'".$hostname."'\n";
			echo "'".$ips."'\n";
			$addserver->id_folder_servers = (int) $GLOBALS["CONF_WEBISSUES_FOLDER_SERVERS"];
			$addserver->hostname = $hostname;
			$addserver->description = $hostname;
			$addserver->use = "Production";
			$addserver->ipsaddress = $ips;

			try 
			{
				$param = new SoapParam($addserver, 'tns:type_addserver');
				$result = $GLOBALS["clientsoap"]->__call('addserver', array('type_addserver'=>$param));
			}
			catch (SoapFault $e) 
			{
				echo $e->getMessage()."\n";
			} 
		}

		fclose($fp1);
		fclose($fp2);
	}
}
