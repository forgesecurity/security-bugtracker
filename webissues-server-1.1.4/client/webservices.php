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

		if($this->authws())
		{
			$req = (array) $req;
			$userManager = new System_Api_UserManager();
			try {
				$id_user = $userManager->addUser( $req["login"], $req["username"], $req["password"], false );
				
                $tab = array(
                        array(
                            'id_user' => $id_user,
                            )
                        );

                return $tab;
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function find_targets($req, $type)
	{
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
            throw new SoapFault("Server", "System_Api_Error $ex");
		}

		return $targets;
	}

    // Gestion des droits bon choix de test
	function getparamsfromalertid($req)
	{
		$req = (array) $req;

		if($this->authws())
		{
			$typeManager = new System_Api_TypeManager();
			$projectManager = new System_Api_ProjectManager();
			$issueManager = new System_Api_IssueManager();
			$userManager = new System_Api_UserManager();

			try {
				$issuescan = $issueManager->getIssue( $req["id_alert"] );
				$project = $projectManager->getProject( $issuescan["project_id"] );
				$id_folder_bugs = 0;
				$projects[0] = $project;
				$folders = $projectManager->getFoldersForProjects( $projects );
				foreach ( $folders as $folder ) {
					if($folder["type_id"] == $GLOBALS['CONF_ID_TYPE_FOLDER_BUGS']) // 2 = TYPE_ID BUGS
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
							case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY']: $severity = $attribute["attr_value"]; break;
							case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID']: $targetid = $attribute["attr_value"]; break;
							case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID']: $taskid = $attribute["attr_value"]; break;
							case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID']: $reportid = $attribute["attr_value"]; break;
							case $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID']: $alertid = $attribute["attr_value"]; break;
							default: break;
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
                else
                    throw new SoapFault("Server", $GLOBALS['UNKNOWN_ALERT']);
                
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function finishscan($req){

		$req = (array) $req;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$typeManager = new System_Api_TypeManager();

			$issuescan = $issueManager->getIssue( $req["id_scan"] );
			if(!empty($req["data_report"]))
			{
				$path = "./reports_tmp/html_report_".$req["id_scan"].".html";
				file_put_contents($path, urldecode($req["data_report"]));
				$size = filesize($path);
				$attachment = System_Core_Attachment::fromFile( $path, $size, "report.html" );
				$issueManager->addFile($issuescan, $attachment, "report.html", "html_report" );
				unlink($path);
			}

			try {

				$parser = new System_Api_Parser();
				$parser->setProjectId( $issuescan["project_id"] );

				$attributetime = $typeManager->getAttributeTypeForIssue( $issuescan, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME'] );
				$valuetime = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], "finished" );
				$issueManager->setValue( $issuescan, $attributetime, $valuetime );
				
                $tab = array(
                        array(
                            'result' => true
                            )
                        );

                return $tab;

			}  
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function run_openvas($req, $targets){

		$issueId = $this->common_scan($req, $targets);

		$issueManager = new System_Api_IssueManager();
		$typeManager = new System_Api_TypeManager();

		try
		{
			if($issueId)
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

				if(!empty($id_target) && !empty($id_task) && !empty($id_report) && !empty($id_alert))
				{
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
				else
                    throw new SoapFault("Server", $GLOBALS['ERROR_OPENVAS']);
			}
                throw new SoapFault("Server", $GLOBALS['ZERO_TARGETS']);
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

	function run_arachni($req, $targets)
	{
		return $this->common_scan($req, $targets);
	}

	function run_sslscan($req, $targets)
	{
		return $this->common_scan($req, $targets);
	}

	function common_scan($req, $targets)
	{
        $issueId = 0;
		$issueManager = new System_Api_IssueManager();
		$projectManager = new System_Api_ProjectManager();
		$typeManager = new System_Api_TypeManager();

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
		}
		catch ( System_Api_Error $ex ) {
			$this->logp( $ex );
            throw new SoapFault("Server", "System_Api_Error $ex");
		}
		
        return $issueId;
	}

	function addscan($req){

		$req = (array) $req;

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
				case "arachni": 
					$targets = $this->find_targets($req, "web");
					$issueId = $this->run_arachni($req, $targets);
					break;
				case "sslscan": 
					$targets = $this->find_targets($req, "web");
					$issueId = $this->run_sslscan($req, $targets);
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
                    throw new SoapFault("Server", $GLOBALS['UNKNOWN_TOOL']);
					break;
			}
			
			$tab = array(
				array(
					'id_scan' => $issueId
				     )
			    );

            return $tab;
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
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

	function deleteurl($req){

		$req = (array) $req;
		$req["id_issue"] = $req["id_url"];
		$tab = $this->deleteissue($req);
		return $tab;
	}

	function deleteissue($req){

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
				
				$tab = array(
				array(
					'result' => true
				     )
			    );

                return $tab;
		
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}


	function addurl($req){

		$req = (array) $req;

		if($this->authws())
		{ 
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			try {


				$this->logp( "url = ".$req["url"] );
				//if(filter_var($req["url"], FILTER_VALIDATE_URL))
				//{
				$this->logp( "FILTER_VALIDATE_URL url = ".$req["url"] );
				$folder = $projectManager->getFolder( $req["id_folder_web"] );

				$duplicate = false;
				$issues = $issueManager->getIssues($folder);
				foreach ($issues as $issue) {
					if($issue["issue_name"] == $req["name"]) 
					{
						$duplicate = true;
						/*
						$req["id_url"] = $issue["issue_id"];
						$res = $this->editurl($req);
						if($res[0]["result"])
							$issueId = $issue["issue_id"];
                        */
						break;
					}
				}

				if(!$duplicate)
				{
					$parser = new System_Api_Parser();
					$parser->setProjectId( $folder[ 'project_id' ] );

					$issueId = $issueManager->addIssue( $folder, $req["name"]);
					$issue = $issueManager->getIssue( $issueId );
					$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

					$attributeurl = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'] );
					$value = $parser->convertAttributeValue( $attributeurl[ 'attr_def' ], $req["url"] );
					$issueManager->setValue( $issue, $attributeurl, $value );
					
					$tab = array(
                        array(
                            'id_url' => $issueId
                            )
                        );

                    return $tab;
				}
                else
                    throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
				//}

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}


	function editurl($req){

		$req = (array) $req;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			try {

				$this->logp( "url = ".$req["url"] );
				//if(filter_var($req["url"], FILTER_VALIDATE_URL))
				//{
				$folder = $projectManager->getFolder( $req["id_folder_web"] );
				$url = $issueManager->getIssue( $req["id_url"] );
				$issueManager->moveIssue( $url, $folder );
				$issueManager->renameIssue( $url, $req["name"] );
				$desc = $issueManager->getDescription( $url );
				$issueManager->editDescription( $desc, $req["description"], System_Const::TextWithMarkup );

				$parser = new System_Api_Parser();
				$parser->setProjectId( $folder[ 'project_id' ] );

				$attributeurl = $typeManager->getAttributeTypeForIssue( $url, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'] );
				$value = $parser->convertAttributeValue( $attributeurl[ 'attr_def' ], $req["url"] );
				$issueManager->setValue( $url, $attributeurl, $value );

                $tab = array(
                        array(
                            'result' => true
                            )
                        );

                return $tab;
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}


	function geturls($req){
	
		$req = (array) $req;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

			try 
			{
				$folder = $projectManager->getFolder( $req["id_folder_web"] );
				$urls = $issueManager->getIssues( $folder );

				foreach($urls as $url)
				{
					$url = $issueManager->getIssue( $url["issue_id"] );

					$attr_value = "";
					$attributes = $issueManager->getAttributeValuesForIssue($url);
					foreach($attributes as $attribute)
					{
						if($attribute["attr_id"] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_WEB_URL'])
						{
							$attr_value = $attribute["attr_value"];
							break;
						}
					}

					$this->logp( "geturls = ".$attr_value );

					$arr = array(
							'id_url' => $url["issue_id"],
							'name' => $url["issue_name"],
							'url' => $attr_value
						    );

                    $result_array = array();
					array_push($result_array, $arr);
                    return $result_array;
				}
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		throw new SoapFault("Server", $GLOBALS['UNKNOWN_URL']);
	}



	function addcode($req){

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

					$duplicate = false;
					$issues = $issueManager->getIssues($folder);
					foreach ($issues as $issue) {
						if($issue["issue_name"] == $req["name"]) 
						{
							$duplicate = true;
							/*
							$req["id_code"] = $issue["issue_id"];
							$res = $this->editcode($req);
							if($res[0]["result"])
								$issueId = $issue["issue_id"];
*/
							break;
						}
					}

					if(!$duplicate)
					{
						$parser = new System_Api_Parser();
						$parser->setProjectId( $folder[ 'project_id' ] );

						$issueId = $issueManager->addIssue( $folder, $req["name"]);
						$issue = $issueManager->getIssue( $issueId );
						$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

						$attributecode = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'] );
						$value = $parser->convertAttributeValue( $attributecode[ 'attr_def' ], $req["code"] );
						$issueManager->setValue( $issue, $attributecode, $value );
						
                        $tab = array(
                                array(
                                    'id_code' => $issueId
                                    )
                                );

                        return $tab;
					}
					else
                        throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
				}
                else
                    throw new SoapFault("Server", $GLOBALS['CODES_FILTER_INVALID']);

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}


	function editcode($req){

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

					$attributecode = $typeManager->getAttributeTypeForIssue( $code, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'] );
					$value = $parser->convertAttributeValue( $attributecode[ 'attr_def' ], $req["code"] );
					$issueManager->setValue( $code, $attributecode, $value );

                    $tab = array(
                            array(
                                'result' => true
                                )
                            );

                    return $tab;
				}
				else
                    throw new SoapFault("Server", $GLOBALS['CODES_FILTER_INVALID']);
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}


	function getcodes($req){

		$req = (array) $req;

		if($this->authws())
		{
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();
			$typeManager = new System_Api_TypeManager();

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
						if($attribute["attr_id"] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_CODES_PATH'])
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

                    $result_array = array();
					array_push($result_array, $arr);
                    return $result_array;
				}
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);

		throw new SoapFault("Server", $GLOBALS['UNKNOWN_CODE']);
	}


	function addserver($req){

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
					if(!filter_var($ip, FILTER_VALIDATE_IP) && !(filter_var($ip, FILTER_VALIDATE_URL)))
					{
						$ips_ok = false;
						$this->logp( $ip." doesn't match the filter" );
                        throw new SoapFault("Server", $GLOBALS['IPS_FILTER_INVALID']);
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
							/*
							$req["id_server"] = $issue["issue_id"];
							$res = $this->editserver($req);
							if($res[0]["result"])
								$issueId = $issue["issue_id"];
                            */
							break;
						}
					}

					if(!$duplicate)
					{
						$parser = new System_Api_Parser();
						$parser->setProjectId( $folder[ 'project_id' ] );

						$issueId = $issueManager->addIssue( $folder, $req["hostname"]);
						$issue = $issueManager->getIssue( $issueId );
						$issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );

						$attributeuse = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE'] );
						$value = $parser->convertAttributeValue( $attributeuse[ 'attr_def' ], $req["use"] );
						$issueManager->setValue( $issue, $attributeuse, $value );

						$attributeips = $typeManager->getAttributeTypeForIssue( $issue, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS'] );
						$value = $parser->convertAttributeValue( $attributeips[ 'attr_def' ], $req["ipsaddress"] );
						$issueManager->setValue( $issue, $attributeips, $value );
						
                        $tab = array(
                                array(
                                    'id_server' => $issueId
                                    )
                                );

                        return $tab;
					}
					else
                        throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
				}

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function getserverfromname($req){

		$req = (array) $req;

		if($this->authws())
		{ 
			$issueManager = new System_Api_IssueManager();
			$projectManager = new System_Api_ProjectManager();

			try {
				$folder = $projectManager->getFolder( $req["id_folder_servers"] );
				$issues = $issueManager->getIssues($folder);
				
				foreach ($issues as $issue) {
					if($issue["issue_name"] == $req["hostname"]) 
					{
						$tab = array(
                        array(
                            'id_server' => $issue["issue_id"]
                            )
                        );

                        return $tab;
					}
				}
				
                throw new SoapFault("Server", $GLOBALS['UNKNOWN_SERVER']);
				

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function editserver($req){

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
					if(!filter_var($ip, FILTER_VALIDATE_IP) && !(filter_var($ip, FILTER_VALIDATE_URL)))
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

					$attributeuse = $typeManager->getAttributeTypeForIssue( $server, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE'] );
					$value = $parser->convertAttributeValue( $attributeuse[ 'attr_def' ], $req["use"] );
					$issueManager->setValue( $server, $attributeuse, $value );

					$attributeips = $typeManager->getAttributeTypeForIssue( $server, $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS'] );
					$value = $parser->convertAttributeValue( $attributeips[ 'attr_def' ], $req["ipsaddress"] );
					$issueManager->setValue( $server, $attributeips, $value );

                    $tab = array(
                            array(
                                'result' => true
                                )
                            );

                    return $tab;
				}
				else
                    throw new SoapFault("Server", $GLOBALS['IPS_FILTER_INVALID']);
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function addissue($req){

		$req = (array) $req;

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
						$issueduplicate = $issueManager->getIssue( $issue["issue_id"] );
						$type = $typeManager->getIssueTypeForFolder( $folder );
						$rows = $typeManager->getAttributeTypesForIssueType( $type );

						foreach ( $rows as $row ) 
						{
							$this->logp( "attr_value = ".$row[ 'attr_value' ]." == req_cve ".$req["cve"]." == req_cwe ".$req["cwe"]." == req_target ".$req["target"]." == attr_id =".$row[ 'attr_id' ]." == true id attribute == ".$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET'] );
							if( $row[ 'attr_value' ] != $req["target"] && $row[ 'attr_id' ] == $GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET'])
							{
								$duplicate = true;
								break 2;
							}
						}
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

					$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET']] = "target";
					$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE']] = "cve";
					$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CWE']] = "cwe";

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

					foreach ( $rows as $attribute ) {
						$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$attribute["attr_id"]]] );
						$issueManager->setValue( $issue, $attribute, $value );
					}
				
                    $tab = array(
                            array(
                                'id_issue' => $issueId
                                )
                            );

                    return $tab;
                }
                else
                    throw new SoapFault("Server", $GLOBALS['DUPLICATE_OBJECT']);
                
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function editissue($req){

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

				$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_TARGET']] = "target";
				$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CVE']] = "cve";
				$name_ws[$GLOBALS['CONF_ID_ATTRIBUTE_FOLDER_BUGS_CWE']] = "cwe";

				foreach ( $rows as $idattribute => $attribute ) {
					$value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$attribute["attr_id"]]] );
					$issueManager->setValue( $issue, $attribute, $value );
				}

                $tab = array(
                        array(
                            'result' => true
                            )
                        );

                return $tab;
		
			} 
			catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function addmember($req){

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
				
                $tab = array(
                        array(
                            'result' => true
                            )
                        );

                return $tab;
                
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function deletemember($req){

		$req = (array) $req;

		if($this->authws())
		{
			$projectManager = new System_Api_ProjectManager();
			$userManager = new System_Api_UserManager();

			try {
				$user = $userManager->getUser( $req["id_user"] );
				$project = $projectManager->getProject( $req["id_project"]);
				$userManager->grantMember( $user, $project, System_Const::NoAccess );
				
				$tab = array(
				array(
					'result' => true
				     )
			    );

                return $tab;
		
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function deleteproject($req){

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
				
                $tab = array(
                array(
                    'result' => true
                    )
                );

                return $tab;
		
			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function editproject($req){

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

				$tab = array(
				array(
					'result' => true
				     )
			    );

                return $tab;

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}

	function addproject($req){

		$req = (array) $req;

		if($this->authws())
		{
			try {
				$typeManager = new System_Api_TypeManager();
				$projectManager = new System_Api_ProjectManager();
				$type = $typeManager->getIssueType($GLOBALS['CONF_ID_TYPE_FOLDER_BUGS']); // Id bugs
				$projectId = $projectManager->addProject($req["name"]);
				$project = $projectManager->getProject( $projectId );

				if ( $req["description"] != '' ) {
					$projectManager->addProjectDescription( $project, $req["description"], System_Const::TextWithMarkup);
				}

				$type_folder_servers = $typeManager->getIssueType( $GLOBALS['CONF_ID_TYPE_FOLDER_SERVERS'] );
				$type_folder_codes = $typeManager->getIssueType( $GLOBALS['CONF_ID_TYPE_FOLDER_CODES'] );
				$type_folder_web = $typeManager->getIssueType( $GLOBALS['CONF_ID_TYPE_FOLDER_WEB'] );
				$type_folder_scans = $typeManager->getIssueType( $GLOBALS['CONF_ID_TYPE_FOLDER_SCANS'] );

				$folderId1 = $projectManager->addFolder( $project, $type, "Bugs" );
				$folderId2 = $projectManager->addFolder( $project, $type_folder_servers, "Servers" );
				$folderId3 = $projectManager->addFolder( $project, $type_folder_codes, "Codes" );
				$folderId4 = $projectManager->addFolder( $project, $type_folder_web, "Web" );
				$folderId5 = $projectManager->addFolder( $project, $type_folder_scans, "Scans" );
				
                $tab = array(
				array(
					'id_project' => $projectId,
					'id_folder_bugs' => $folderId1,
					'id_folder_servers' => $folderId2,
					'id_folder_codes' => $folderId3,
					'id_folder_web' => $folderId4,
					'id_folder_scans' => $folderId5
				     )
			    );

                return $tab;

			} catch ( System_Api_Error $ex ) {
				$this->logp( $ex );
                throw new SoapFault("Server", "System_Api_Error $ex");
			}
		}
		else
            throw new SoapFault("Server", $GLOBALS['FAULT_AUTHENTICATION']);
	}
}

System_Bootstrap::run( 'System_Web_Service');

ini_set('soap.wsdl_cache_enabled', 0);
$serversoap=new SoapServer("webservices.wsdl");
$serversoap->setClass("webservice_server");
$serversoap->handle();



