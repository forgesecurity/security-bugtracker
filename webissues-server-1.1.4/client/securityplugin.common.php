<?php
/**************************************************************************
 * This file is part of the WebIssues Server program - security plugin
 * Copyright (C) 2006 Michał Męciński
 * Copyright (C) 2007-2015 WebIssues Team
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

require_once( '../system/bootstrap.inc.php' );

include( 'securityplugin.conf.php' );
include( 'securityplugin.lang.php' );

class type_run_openvas
{
	public $target;
	public $id_config;
	public $id_scan;
}

class Common_SecurityPlugin
{
	public static function logp($ex)
	{
		$fp = fopen("webservices.log","a+");
		fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
		fclose($fp);
	}

	public static function run_dependencycheck($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function run_arachni($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function run_zap($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function run_sslscan($req, $targets)
	{
		return Common_SecurityPlugin::common_scan($req);
	}

	public static function find_targets($req, $type)
	{
		$targets = array();

		try
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();

			$id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_SERVERS'];
			$id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS'];
			if($type == "static")
			{
				$id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_CODES'];
				$id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'];
			}
			else if($type == "web")
			{
				$id_type = $GLOBALS['CONF_ID_TYPE_FOLDER_WEB'];
				$id_attribute = $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'];
			}

			$folderscan = $projectManager->getFolder( $req["id_folder_scans"] );
			$project = $projectManager->getProject( $folderscan[ 'project_id' ] );

			Common_SecurityPlugin::logp( "FOLDERSCAN = ".$folderscan[ 'project_id' ] );

			$id_folder_targets = 0;
			$projects[0] = $project;
			$folders = $projectManager->getFoldersForProjects( $projects );
			foreach ( $folders as $folder ) 
			{
				if($folder["type_id"] == $id_type)
				{
					$id_folder_targets = $folder["folder_id"];
					break;
				}
			}

			if($id_folder_targets > 0)
			{
				Common_SecurityPlugin::logp( "id_folder_targets = ".$id_folder_targets );
				$nbtargets = 0;
				$foldertargets = $projectManager->getFolder( $id_folder_targets );
				$targets = $issueManager->getIssues($foldertargets);
				foreach ( $targets as $idtarget => $target ) {
					$attributes = $issueManager->getAttributeValuesForIssue( $target );
					foreach ( $attributes as $idattribute => $attribute ) {
						if($attribute["attr_id"] == $id_attribute)
						{
							Common_SecurityPlugin::logp( "target = ".$attribute["attr_value"] );
							$targets[$nbtargets] = $attribute["attr_value"];
							$nbtargets ++;
						}
					}
				}
			}
		} catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			//throw new SoapFault("Server", "System_Api_Error $ex");
		}

		if(count($targets) == 0)
			throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);

		return $targets;
	}

	public static function common_scan($req)
	{
		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		try {
			if(empty($req["time"]))
				$req["time"] = "stopped";

			$folderscan = $projectManager->getFolder( $req["id_folder_scans"] );
			$issueId = $issueManager->addIssue( $folderscan, $req["name"]);
			$issue = $issueManager->getIssue( $issueId );
			$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

			$parser = new System_Api_Parser();
			$parser->setProjectId( $folderscan[ 'project_id' ] );

			$attributetime = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME'] );
			$valuetime = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], $req["time"] );

			$attributetool = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TOOL'] );
			$valuetool = $parser->convertAttributeValue( $attributetool[ 'attr_def' ], $req["tool"] );

			$attributeseve = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY'] );
			$valueseve = $parser->convertAttributeValue( $attributeseve[ 'attr_def' ], $req["filter"] );

			$issueManager->setValue( $issue, $attributetime, $valuetime );
			$issueManager->setValue( $issue, $attributetool, $valuetool );
			$issueManager->setValue( $issue, $attributeseve, $valueseve );
		}
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
			throw new SoapFault("Server", "System_Api_Error $ex");
		}

		return $issueId;
	}

	public static function run_openvas($req, $targets)
	{
		$issueId = Common_SecurityPlugin::common_scan($req);

		$issueManager = new System_Api_IssueManager();
		$typeManager = new System_Api_TypeManager();

		try
		{
			$issue = $issueManager->getIssue( $issueId );
			$parser = new System_Api_Parser();
			$parser->setProjectId( $issue[ 'project_id' ] );

			$run_openvas = new type_run_openvas();

			for($i = 0; $i < count($targets); $i++)
			{
				if($i == 0)
					$run_openvas->target = $targets[$i];
				else
					$run_openvas->target = $run_openvas->target.",".$targets[$i];
			}

			$run_openvas->id_scan = $issueId;
			$run_openvas->id_config = $req["id_config_openvas"];

			ini_set('default_socket_timeout', 600);
			ini_set('soap.wsdl_cache_enabled', 0);
			$credentials = array('login' => $GLOBALS['CONF_OPENVAS_WS_LOGIN'], 'password' => $GLOBALS['CONF_OPENVAS_WS_PASSWORD']);
			$clientsoap = new SoapClient($GLOBALS['CONF_OPENVAS_WS_ENDPOINT']."?wsdl", $credentials);
			$param = new SoapParam($run_openvas, 'tns:run_openvas');
			$result = $clientsoap->__call('run_openvas',array('run_openvas'=>$param));

			$id_target = $result->result_run_openvas_details->id_target;
			$id_task = $result->result_run_openvas_details->id_task;
			$id_report = $result->result_run_openvas_details->id_report;
			$id_alert = $result->result_run_openvas_details->id_alert;      

			if(empty($id_target) || empty($id_task) || empty($id_report) || empty($id_alert))
			{
				$issueManager->deleteIssue( $issue );
				throw new SoapFault("Server", $GLOBALS['ERROR_OPENVAS']);
			}

			$attribute = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID']);
			$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $id_target );
			$issueManager->setValue( $issue, $attribute, $value);
			$attribute = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID']);
			$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $id_task );
			$issueManager->setValue( $issue, $attribute, $value );
			$attribute = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID']);
			$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $id_report );
			$issueManager->setValue( $issue, $attribute, $value );
			$attribute = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID']);
			$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $id_alert );
			$issueManager->setValue( $issue, $attribute, $value );

			$attributetime = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME'] );
			$valuetime = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], "in progress" );
			$issueManager->setValue( $issue, $attributetime, $valuetime );
		}
		catch ( System_Api_Error $ex ) {
			Common_SecurityPlugin::logp( $ex );
		}

		return $issueId;
	}

	public static function valid_code($code)
	{
		if(!empty($code) && preg_match('/^[A-Za-z0-9_\-\:\/\.&?\=]*$/i', $code))
			return true;

		return false;
	}

	public static function valid_url($url)
	{
		if(filter_var($url, FILTER_VALIDATE_URL))
			return true;

		return false;
	}

	public static function valid_ip($ip)
	{
		if(filter_var($ip, FILTER_VALIDATE_IP))
			return true;

		return false;
	}

	public static function valid_rights($right)
	{
		switch($right)
		{
			case "member": break;
			case "admin": break;
			default: return false;
		}

		return true;
	}

	public static function valid_tool($tool)
	{
		switch($tool)
		{
			case "openvas": break;
			case "dependency-check": break;
			case "arachni": break;
			case "sslscan": break;
			case "zap": break;
			case "openscat": break;
			case "sonar": break;
			default: return false;
		}

		return true;
	}

	public static function valid_time($time)
	{
		switch($time)
		{
			case "stopped": break;
			case "in progress": break;
			case "finished": break;
			default: return false;
		}

		return true;
	}

	public static function valid_severity($severity)
	{
		switch($severity)
		{
			case "info": break;
			case "minor": break;
			case "medium": break;
			case "high": break;
			default: return false;
		}

		return true;
	}

	public static function valid_use($use)
	{
		switch($use)
		{
			case "Development": break;
			case "Test": break;
			case "Production": break;
			default: return false;
		}

		return true;
	}

	public static function valid_name($name)
	{
		if(Common_SecurityPlugin::valid_string($name) && strlen($name) > 1 && strlen($name) < 150)
			return true;

		return false;
	}

	public static function valid_string($string)
	{
		return is_string($string);
	}

	public static function valid_id($id)
	{
		if(Common_SecurityPlugin::valid_int($id))
			return true;

		return false;
	}

	public static function valid_int($int)
	{
		return is_int($int);
	}
}

?>
