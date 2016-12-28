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

$credentials = array('login' => $CONF_WEBISSUES_OPENVAS_LOGIN, 'password' => $CONF_WEBISSUES_OPENVAS_PASSWORD);
$clientsoap = new SoapClient($CONF_WEBISSUES_WS_ENDPOINT."?wsdl", $credentials);

add_assets_servers();

$addscan = new type_addscan();
$addscan->id_folder_scans = $CONF_WEBISSUES_FOLDER_SCANS;
$addscan->name = "scan_".rand()."_openvas_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->description = "scan_".rand()."_openvas_".$CONF_WEBISSUES_FOLDER_SCANS;
$addscan->tool = "openvas";
$addscan->filter = "medium";

$param = new SoapParam($addscan, 'tns:type_addscan');
$result = $clientsoap->__call('addscan', array('type_addscan'=>$param));

?>
