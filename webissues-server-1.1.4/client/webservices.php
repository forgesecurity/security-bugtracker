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

class type_run_openvas
{
	public $target;
	public $id_config;
	public $id_scan;
}

class webservice_server
{
	function authws()
	{
		$sessionManager = new System_Api_SessionManager();
		try {
			$sessionManager->login( $_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']);
		} 
		catch ( System_Api_Error $ex ) {
			$this->logp( $ex );
			return false;
		}

		return true;
	}

	function logp($ex)
	{
		$fp = fopen("webservices.log","a+");
		fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
		fclose($fp);
	}

	function adduser($req){

		$id_user = 0;

		if($this->authws())
		{
			$req = (array) $req;
			$userManager = new System_Api_UserManager();
			try {
				$id_user = $userManager->addUser( $req["login"], $req["username"], $req["password"], false );
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'id_user' => $id_user,
				     )
			    );

		return $tab;
	}

	function find_targets($req, $type)
	{
		include("securityplugin.conf.php");

		try
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();

			$id_type = $CONF_ID_TYPE_FOLDER_SERVERS;
			$id_attribute = $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS;
			if($type == "static")
			{
				$id_type = $CONF_ID_TYPE_FOLDER_CODES;
				$id_attribute = $CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH;
			}

			$folderscan = $projectManager->getFolder( $req["id_folder_scans"] );
			$project = $projectManager->getProject( $folderscan[ 'project_id' ] );
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
				$nbtargets = 0;
				$targets = array();
				$foldertargets = $projectManager->getFolder( $id_folder_targets );
				$targets = $issueManager->getIssues($foldertargets);
				foreach ( $targets as $idtarget => $target ) {
					$attributes = $issueManager->getAttributeValuesForIssue( $target );
					foreach ( $attributes as $idattribute => $attribute ) {
						if($attribute["attr_id"] == $id_attribute)
						{
							$targets[$nbtargets] = $attribute["attr_value"];
							$nbtargets ++;
						}
					}
				}
			}
		} catch ( System_Api_Error $ex ) {
			$this->logp( $ex );
		}

		return $targets;
	}

	function getparamsfromalertid($req)
	{
		$req = (array) $req;

		$id_folder_bugs = 0;
		$id_target = 0;
		$id_task = 0;
		$id_report = 0;
		$id_alert = 0;
		$severity = 0;

		if($this->authws())
		{
			$typeManager = new System_Api_TypeManager();
			$projectManager = new System_Api_ProjectManager();
			$issueManager = new System_Api_IssueManager();
			$userManager = new System_Api_UserManager();

			/*
			   if(!System_Api_Principal::getCurrent()->isAuthenticated())
			   {
			   $sessionManager = new System_Api_SessionManager();
			   try {
			   $sessionManager->loginAs( "admin");
			   } catch ( System_Api_Error $ex ) {
			   $this->logp( $ex );
			   }
			   }
			 */

			include("securityplugin.conf.php");

			try {
				$this->logp("run_openvas getparamsfromalertid id_alert = '".$req["id_alert"]."'");
				$issuescan = $issueManager->getIssue( $req["id_alert"] );
				$project = $projectManager->getProject( $issuescan["project_id"] );
				$id_folder_bugs = 0;
				$projects[0] = $project;
				$folders = $projectManager->getFoldersForProjects( $projects );
				foreach ( $folders as $folder ) {
					if($folder["type_id"] == 2) // 2 = TYPE_ID BUGS
					{
						$id_folder_bugs = $folder["folder_id"];
						break;
					}
				}

				if($id_folder_bugs > 0)
				{
					$attributes = $issueManager->getAttributeValuesForIssue( $issuescan );
					foreach ( $attributes as $attribute ) {
						switch($attribute["attr_id"])
						{
							case $CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY: $severity = $attribute["attr_value"]; break;
							case $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID: $targetid = $attribute["attr_value"]; break;
							case $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID: $taskid = $attribute["attr_value"]; break;
							case $CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID: $reportid = $attribute["attr_value"]; break;
							case $CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID: $alertid = $attribute["attr_value"]; break;
							default: break;
						}
					}
				}

				switch($severity)
				{
					case 'info':$severity = 1;break;
					case 'minor':$severity = 1;break;
					case 'medium':$severity = 2;break;
					case 'high':$severity = 3;break;
					default:$severity = 1;break;
				}
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'id_folder_bugs' => $id_folder_bugs,
					'id_target' => $targetid,
					'id_task' => $taskid,
					'id_report' => $reportid,
					'id_alert' => $alertid,
					'severity' => $severity
				     )
			    );

		return $tab;
	}

	function finishscan($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$typeManager = new System_Api_TypeManager();

			$issuescan = $issueManager->getIssue( $req["id_scan"] );

			include("securityplugin.conf.php");

			try {

				$parser = new System_Api_Parser();
				$parser->setProjectId( $issuescan["project_id"] );

				$attributetime = $typeManager->getAttributeTypeForIssue( $issuescan, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME );
				$valuetime = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], "finished" );
				$issueManager->setValue( $issuescan, $attributetime, $valuetime );
				$result = true;

			}  
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}

	function run_openvas($req, $targets){

		$issueId = $this->common_scan($req, $targets);

		$issueManager = new System_Api_IssueManager();
		$typeManager = new System_Api_TypeManager();

		include("securityplugin.conf.php");

		try
		{
			if($issueId)
			{
				$this->logp("run_openvas targets = ".$targets);

				$issue = $issueManager->getIssue( $issueId );
				$parser = new System_Api_Parser();
				$parser->setProjectId( $issue[ 'project_id' ] );

				$run_openvas = new type_run_openvas();

				for($i = 0; $i < count($targets); $i++)
				{
					$this->logp("run_openvas targets $i = ".$targets[$i]);
					if($i == 0)
						$run_openvas->target = $targets[$i];
					else
						$run_openvas->target = $run_openvas->target.",".$targets[$i];
				}


				$this->logp("run_openvas targets = ".$run_openvas->target);
				$run_openvas->id_scan = $issueId;
				$run_openvas->id_config = $req["id_config_openvas"];

				ini_set('default_socket_timeout', 600);
				ini_set('soap.wsdl_cache_enabled', 0);
				$credentials = array('login' => $CONF_OPENVAS_WS_LOGIN, 'password' => $CONF_OPENVAS_WS_PASSWORD);
				$clientsoap = new SoapClient($CONF_OPENVAS_WS_ENDPOINT."?wsdl", $credentials);
				$param = new SoapParam($run_openvas, 'tns:run_openvas');
				$result = $clientsoap->__call('run_openvas',array('run_openvas'=>$param));

				$id_target = $result->result_run_openvas_details->id_target;
				$id_task = $result->result_run_openvas_details->id_task;
				$id_report = $result->result_run_openvas_details->id_report;
				$id_alert = $result->result_run_openvas_details->id_alert;      

				if(!empty($id_target) && !empty($id_task) && !empty($id_report) && !empty($id_alert))
				{
					$attribute = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID);
					$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $id_target );
					$issueManager->setValue( $issue, $attribute, $value);
					$attribute = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID);
					$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $id_task );
					$issueManager->setValue( $issue, $attribute, $value );
					$attribute = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID);
					$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $id_report );
					$issueManager->setValue( $issue, $attribute, $value );
					$attribute = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID);
					$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $id_alert );
					$issueManager->setValue( $issue, $attribute, $value );

					$attributetime = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME );
					$valuetime = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], "in progress" );
					$issueManager->setValue( $issue, $attributetime, $valuetime );
				}
			}
		}
		catch ( System_Api_Error $ex ) {
			$this->logp( $ex );
		}

		return $issueId;
	}

	function run_dependencycheck($req, $targets)
	{
		return $this->common_scan($req, $targets);
	}

	function common_scan($req, $targets)
	{
		$issueId = 0;

		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

		include("securityplugin.conf.php");

		try {
			if(empty($req["time"]))
				$req["time"] = "stopped";

			if(count($targets) > 0)
			{
				$folderscan = $projectManager->getFolder( $req["id_folder_scans"] );
				$issueId = $issueManager->addIssue( $folderscan, $req["name"]);
				$issue = $issueManager->getIssue( $issueId );
				$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

				$parser = new System_Api_Parser();
				$parser->setProjectId( $folderscan[ 'project_id' ] );

				$attributetime = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME );
				$valuetime = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], $req["time"] );

				$attributetool = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TOOL );
				$valuetool = $parser->convertAttributeValue( $attributetool[ 'attr_def' ], $req["tool"] );

				$attributeseve = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY );
				$valueseve = $parser->convertAttributeValue( $attributeseve[ 'attr_def' ], $req["filter"] );

				$issueManager->setValue( $issue, $attributetime, $valuetime );
				$issueManager->setValue( $issue, $attributetool, $valuetool );
				$issueManager->setValue( $issue, $attributeseve, $valueseve );
			}
		}
		catch ( System_Api_Error $ex ) {
			$this->logp( $ex );
		}

		return $issueId;
	}

	function addscan($req){

		$req = (array) $req;
		$issueId = 0;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			switch($req["tool"])
			{
				case "openvas": 
					$targets = $this->find_targets($req, "dynamic");
					$issueId = $this->run_openvas($req, $targets);
					break;
				case "dependency-check": 
					$targets = $this->find_targets($req, "static");
					$issueId = $this->run_dependencycheck($req, $targets);
					break;
				case "sensorlabs": 
					$targets = $this->find_targets($req, "static");
					//$this->run_sensorlabs();
					break;
				case "openscat": 
					$targets = $this->find_targets($req, "static");
					//$this->run_openscat();
					break;
				case "sonar": 
					$targets = $this->find_targets($req, "static");
					//$this->run_sonar();
					break;
				default: 
					break;
			}
		}

		$tab = array(
				array(
					'id_scan' => $issueId
				     )
			    );

		return $tab;
	}

	function deletescan($req){

		$req = (array) $req;
		$req["id_issue"] = $req["id_scan"];
		$tab = $this->deleteissue($req);
		return $tab;
	}

	function deleteserver($req){

		$req = (array) $req;
		$req["id_issue"] = $req["id_server"];
		$tab = $this->deleteissue($req);
		return $tab;

	}

	function deletecode($req){

		$req = (array) $req;
		$req["id_issue"] = $req["id_code"];
		$tab = $this->deleteissue($req);
		return $tab;

	}

	function deleteissue($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{	
			try 
			{
				$issueManager = new System_Api_IssueManager();
				$issue = $issueManager->getIssue( $req["id_issue"] );
				$desc = $issueManager->getDescription( $issue );
				$issueManager->deleteIssue( $issue );
				$issueManager->deleteDescription( $descr );
				$result = true;
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}

	function addcode($req){

		$result = false;
		$req = (array) $req;
		$issueId = 0;

		if($this->authws())
		{ 
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			try {


				if(preg_match('/^[A-Za-z0-9_\-\:\/\.&?\=]*$/i', $req["code"]))
				{
					$folder = $projectManager->getFolder( $req["id_folder_codes"] );

					$duplicate = false;
					$issues = $issueManager->getIssues($folder);
					foreach ($issues as $issue) {
						if($issue["issue_name"] == $req["name"]) 
						{
							$duplicate = true;
							$req["id_code"] = $issue["issue_id"];
							$res = $this->editcode($req);
							if($res[0]["result"])
								$issueId = $issue["issue_id"];

							break;
						}
					}

					if(!$duplicate)
					{
						$parser = new System_Api_Parser();
						$parser->setProjectId( $folder[ 'project_id' ] );

						include("securityplugin.conf.php");

						$issueId = $issueManager->addIssue( $folder, $req["name"]);
						$issue = $issueManager->getIssue( $issueId );
						$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

						$attributecode = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH );
						$value = $parser->convertAttributeValue( $attributecode[ 'attr_def' ], $req["code"] );
						$issueManager->setValue( $issue, $attributecode, $value );
					}
				}

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'id_code' => $issueId
				     )
			    );

		return $tab;
	}


	function editcode($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			try {

				if(preg_match('/^[A-Za-z0-9_\-\:\/\.&?\=]*$/i', $req["code"]))
				{
					$folder = $projectManager->getFolder( $req["id_folder_codes"] );
					$code = $issueManager->getIssue( $req["id_code"] );
					$issueManager->moveIssue( $code, $folder );
					$issueManager->renameIssue( $code, $req["name"] );
					$desc = $issueManager->getDescription( $code );
					$issueManager->editDescription( $desc, $req["description"], System_Const::TextWithMarkup );


					$parser = new System_Api_Parser();
					$parser->setProjectId( $folder[ 'project_id' ] );

					include("securityplugin.conf.php");

					$attributecode = $typeManager->getAttributeTypeForIssue( $code, $CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH );
					$value = $parser->convertAttributeValue( $attributecode[ 'attr_def' ], $req["code"] );
					$issueManager->setValue( $code, $attributecode, $value );

					$result = true;
				}
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}


	function getcodes($req){

		$result_array = array();
		$req = (array) $req;

		$arrtemp = array(
				'id_code' => 0,
				'name' => "",
				'code' => ""
				);

		$codesexist = false;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			include("securityplugin.conf.php");

			try 
			{
				$folder = $projectManager->getFolder( $req["id_folder_codes"] );
				$codes = $issueManager->getIssues( $folder );

				foreach($codes as $code)
				{
					$code = $issueManager->getIssue( $code["issue_id"] );

					$attr_value = "";
					$attributes = $issueManager->getAttributeValuesForIssue($code);
					foreach($attributes as $attribute)
					{
						if($attribute["attr_id"] == $CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH)
						{
							$attr_value = $attribute["attr_value"];
							break;
						}
					}

					$arr = array(
							'id_code' => $code["issue_id"],
							'name' => $code["issue_name"],
							'code' => $attr_value
						    );

					array_push($result_array, $arr);
					$codesexist = true;
				}
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		if(!$codesexist)
			array_push($result_array, $arrtemp);


		return $result_array;
	}


	function addserver($req){

		$result = false;
		$req = (array) $req;
		$issueId = 0;

		if($this->authws())
		{ 
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			try {
				$ips_ok = true;
				$ips = explode(",", $req["ipsaddress"]);
				foreach($ips as $ip)
					if(!filter_var($ip, FILTER_VALIDATE_IP))
					{
						$ips_ok = false;
						$this->logp( "filter validate ip not ok : ".$ip );
					}

				if($ips_ok)
				{
					$folder = $projectManager->getFolder( $req["id_folder_servers"] );

					$duplicate = false;
					$issues = $issueManager->getIssues($folder);
					foreach ($issues as $issue) {
						if($issue["issue_name"] == $req["hostname"]) 
						{
							$duplicate = true;
							$req["id_server"] = $issue["issue_id"];
							$res = $this->editserver($req);
							if($res[0]["result"])
								$issueId = $issue["issue_id"];

							break;
						}
					}

					if(!$duplicate)
					{
						$parser = new System_Api_Parser();
						$parser->setProjectId( $folder[ 'project_id' ] );

						include("securityplugin.conf.php");

						$issueId = $issueManager->addIssue( $folder, $req["hostname"]);
						$issue = $issueManager->getIssue( $issueId );
						$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

						$attributeuse = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE );
						$value = $parser->convertAttributeValue( $attributeuse[ 'attr_def' ], $req["use"] );
						$issueManager->setValue( $issue, $attributeuse, $value );

						$attributeips = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS );
						$value = $parser->convertAttributeValue( $attributeips[ 'attr_def' ], $req["ipsaddress"] );
						$issueManager->setValue( $issue, $attributeips, $value );
					}
				}

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'id_server' => $issueId
				     )
			    );

		return $tab;
	}

	function getserverfromname($req){

		$result = false;
		$req = (array) $req;
		$issueId = 0;

		if($this->authws())
		{ 
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();

			try {
				$folder = $projectManager->getFolder( $req["id_folder_servers"] );

				$duplicate = false;
				$issues = $issueManager->getIssues($folder);
				foreach ($issues as $issue) {
					if($issue["issue_name"] == $req["hostname"]) 
					{
						$issueId = $issue["issue_id"];
						break;
					}
				}

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'id_server' => $issueId
				     )
			    );

		return $tab;
	}

	function editserver($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			try {

				$ips_ok = true;
				$ips = explode(",", $req["ipsaddress"]);
				foreach($ips as $ip)
					if(!filter_var($ip, FILTER_VALIDATE_IP))
						$ips_ok = false;

				if($ips_ok)
				{
					$folder = $projectManager->getFolder( $req["id_folder_servers"] );
					$server = $issueManager->getIssue( $req["id_server"] );
					$issueManager->moveIssue( $server, $folder );
					$issueManager->renameIssue( $server, $req["hostname"] );
					$desc = $issueManager->getDescription( $server );
					$issueManager->editDescription( $desc, $req["description"], System_Const::TextWithMarkup );


					$parser = new System_Api_Parser();
					$parser->setProjectId( $folder[ 'project_id' ] );

					include("securityplugin.conf.php");

					$attributeuse = $typeManager->getAttributeTypeForIssue( $server, $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE );
					$value = $parser->convertAttributeValue( $attributeuse[ 'attr_def' ], $req["use"] );
					$issueManager->setValue( $server, $attributeuse, $value );

					$attributeips = $typeManager->getAttributeTypeForIssue( $server, $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS );
					$value = $parser->convertAttributeValue( $attributeips[ 'attr_def' ], $req["ipsaddress"] );
					$issueManager->setValue( $server, $attributeips, $value );

					$result = true;
				}
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}

	function addissue($req){

		$req = (array) $req;
		$issueId = 0;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();
			$userManager = new System_Api_UserManager();

			try {
				$folder = $projectManager->getFolder( $req["id_folder_bugs"] );

				$duplicate = false;
				$issues = $issueManager->getIssues($folder);
				foreach ($issues as $issue) {
					if($issue["issue_name"] == $req["name"]) 
					{
						$duplicate = true;
						break;
					}
				}

				if(!$duplicate)
				{
					$issueId = $issueManager->addIssue( $folder, $req["name"]);
					$issue = $issueManager->getIssue( $issueId );
					$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

					$type = $typeManager->getIssueTypeForFolder( $folder );
					$rows = $typeManager->getAttributeTypesForIssueType( $type );

					$parser = new System_Api_Parser();
					$parser->setProjectId( $folder[ 'project_id' ] );

					$name_ws[0] = "assigned";
					$name_ws[1] = "state";
					$name_ws[2] = "raison";
					$name_ws[3] = "severity";
					$name_ws[4] = "version";

					if(empty($req["assigned"]))
					{
						$admin = null;
						$members = $userManager->getMembers($folder);
						foreach ($members as $member) {

							if($member["project_access"] == System_Const::AdministratorAccess)
							{
								$admin = $member;
								$user = $userManager->getUser($admin["user_id"]);
								$req["assigned"] = $user["user_name"];
								break;
							}
						}
					}

					foreach ( $rows as $idattribute => $attribute ) {
						$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$idattribute]] );
						$issueManager->setValue( $issue, $attribute, $value );
					}	
				}
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'id_issue' => $issueId
				     )
			    );

		return $tab;
	}

	function editissue($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();

			try {

				$folder = $projectManager->getFolder( $req["id_folder_bugs"] );
				$issue = $issueManager->getIssue( $req["id_issue"] );
				$issueManager->moveIssue( $issue, $folder );
				$issueManager->renameIssue( $issue, $req["name"] );
				$desc = $issueManager->getDescription( $issue );
				$issueManager->editDescription( $desc, $req["description"], System_Const::TextWithMarkup );

				$rows = $issueManager->getAllAttributeValuesForIssue( $issue );
				$parser = new System_Api_Parser();
				$parser->setProjectId( $issue[ 'project_id' ] );

				$name_ws[0] = "assigned";
				$name_ws[1] = "state";
				$name_ws[2] = "raison";
				$name_ws[3] = "severity";
				$name_ws[4] = "version";

				foreach ( $rows as $idattribute => $attribute ) {
					$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$idattribute]] );
					$issueManager->setValue( $issue, $attribute, $value );
				}

				$result = true;
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}

	function addmember($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{
			$projectManager = new System_Api_ProjectManager();
			$userManager = new System_Api_UserManager();

			switch($req["access"])
			{
				case "member":$req["access"] = System_Const::NormalAccess; break;
				case "admin":$req["access"] = System_Const::AdministratorAccess; break;
				default:$req["access"] = System_Const::NormalAccess; break;
			}

			try {
				$user = $userManager->getUser( $req["id_user"] );
				$project = $projectManager->getProject( $req["id_project"] );
				$userManager->grantMember( $user, $project, $req["access"] );
				$result = true;
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}

	function deletemember($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{
			$projectManager = new System_Api_ProjectManager();
			$userManager = new System_Api_UserManager();

			try {
				$user = $userManager->getUser( $req["id_user"] );
				$project = $projectManager->getProject( $req["id_project"]);
				$userManager->grantMember( $user, $project, System_Const::NoAccess );
				$result = true;
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}

	function deleteproject($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{
			try {
				$projectManager = new System_Api_ProjectManager();
				$issueManager = new System_Api_IssueManager();

				$project = $projectManager->getProject( $req["id_project"] );
				$folders = $projectManager->getFoldersForProject( $project );

				foreach ( $folders as $folder )
				{
					$issues = $issueManager->getIssues( $folder );
					foreach ( $issues as $issue )
					{
						$desc = $issueManager->getDescription( $issue );
						$issueManager->deleteIssue( $issue );
						$issueManager->deleteDescription( $descr );
					}

					$projectManager->deleteFolder( $folder );
				}

				$desc = $projectManager->getProjectDescription( $project );
				$projectManager->deleteProjectDescription( $descr );

				//$projectManager->deleteProject( $project, System_Api_ProjectManager::ForceDelete );
				$projectManager->deleteProject( $project);
				$result = true;
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}

	function editproject($req){

		$result = false;
		$req = (array) $req;

		if($this->authws())
		{
			try {
				$projectManager = new System_Api_ProjectManager();
				$project = $projectManager->getProject( $req["id_project"]);
				$projectManager->renameProject( $project, $req["name"] );
				$desc = $projectManager->getProjectDescription( $project );

				if ( $req["description"] != '' ) {
					$projectManager->editProjectDescription( $desc, $req["description"], System_Const::TextWithMarkup);
				}

				$result = true;

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'result' => $result
				     )
			    );

		return $tab;
	}

	function addproject($req){

		$req = (array) $req;

		$projectId = 0;
		$folderId1 = 0;
		$folderId2 = 0;
		$folderId3 = 0;
		$folderId4 = 0;

		if($this->authws())
		{
			try {
				$typeManager = new System_Api_TypeManager();
				$projectManager = new System_Api_ProjectManager();
				$type = $typeManager->getIssueType(2); // Id bugs
				$projectId = $projectManager->addProject($req["name"]);
				$project = $projectManager->getProject( $projectId );

				if ( $req["description"] != '' ) {
					$projectManager->addProjectDescription( $project, $req["description"], System_Const::TextWithMarkup);
				}

				include( 'securityplugin.conf.php' );
				$type_folder_servers = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_SERVERS );
				$type_folder_codes = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_CODES );
				$type_folder_scans = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_SCANS );

				$folderId1 = $projectManager->addFolder( $project, $type, "Bugs" );
				$folderId2 = $projectManager->addFolder( $project, $type_folder_servers, "Servers" );
				$folderId3 = $projectManager->addFolder( $project, $type_folder_codes, "Codes" );
				$folderId4 = $projectManager->addFolder( $project, $type_folder_scans, "Scans" );

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
			}
		}

		$tab = array(
				array(
					'id_project' => $projectId,
					'id_folder_bugs' => $folderId1,
					'id_folder_servers' => $folderId2,
					'id_folder_codes' => $folderId3,
					'id_folder_scans' => $folderId4
				     )
			    );

		return $tab;
	}
}

System_Bootstrap::run( 'System_Web_Service');

ini_set('soap.wsdl_cache_enabled', 0);
$serversoap=new SoapServer("webservices.wsdl");
$serversoap->setClass("webservice_server");
$serversoap->handle();



