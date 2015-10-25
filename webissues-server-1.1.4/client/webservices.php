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
	
	function addscan($req){
	  
	    $result = false;
	    $req = (array) $req;
	    $issueId = 0;
	  
	    if($this->authws())
	    {
	      $issueManager = new System_Api_IssueManager();
	      $projectManager = new System_Api_ProjectManager();
	      $typeManager = new System_Api_TypeManager();
	      
	      include("securityplugin.conf.php");
	      
	      $id_config_openvas = $CONF_ID_OPENVAS;
	      if(isset($req["id_config_openvas"]) && !empty($req["id_config_openvas"]))
		$id_config_openvas = $req["id_config_openvas"];
	      
	      try {
	      
		$folderscan = $projectManager->getFolder( $req["id_folder_scans"] );
		
		$project = $projectManager->getProject( $folderscan[ 'project_id' ] );
		$id_folder_servers = 0;
		$projects[0] = $project;
		$folders = $projectManager->getFoldersForProjects( $projects );
		foreach ( $folders as $folder ) 
		{
		  if($folder["type_id"] == $CONF_ID_TYPE_FOLDER_SERVERS)
		  {
		    $id_folder_servers = $folder["folder_id"];
		    break;
		  }
		}
		
		$nbips = 0;
		$ipsaddress = array();
		$folderservers = $projectManager->getFolder( $id_folder_servers );
		$servers = $issueManager->getIssues($folderservers);
		foreach ( $servers as $idserver => $server ) {
		  $attributes = $issueManager->getAttributeValuesForIssue( $server );
		  foreach ( $attributes as $idattribute => $attribute ) {
		    if($attribute["attr_id"] == $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS)
		    {
		      $ipsaddress[$nbips] = $attribute["attr_value"];
		      $nbips ++;
		    }
		  }
		}
		
		if(empty($req["time"]))
		  $req["time"] = "stopped";
		
		if($id_folder_servers > 0 && $nbips > 0)
		{
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
		
		  $output = shell_exec ("".$CONF_OPENVAS_PATH_OMP." -u ".$CONF_OPENVAS_ADMIN_LOGIN." -w ".$CONF_OPENVAS_ADMIN_PASSWORD." -p 9393 --xml='<create_target><name>webissue".$issueId."</name><hosts>".$ipsaddress[0]."</hosts></create_target>'");
		  preg_match('|<create_target_response id=\"([^"]*)\"|', $output, $matches);
		  $targetid = $matches[1];

		  if($targetid != null)
		  {
		    $output = shell_exec ("".$CONF_OPENVAS_PATH_OMP." -u ".$CONF_OPENVAS_ADMIN_LOGIN." -w ".$CONF_OPENVAS_ADMIN_PASSWORD." -p 9393 --xml='<create_alert><name>webissue".$issueId."</name><condition>Always</condition><event>Task run status changed<data>Done<name>status</name></data></event><method>HTTP Get<data><name>URL</name>http://localhost:8080/webissues-server-1.1.4/client/securityplugin.php?alertscanid=".$issueId."</data></method></create_alert>'");
		    preg_match('|<create_alert_response id=\"([^"]*)\"|', $output, $matches);
		    $alertid = $matches[1];
		  }
		  
		  if(isset($alertid))
		  {
		    $output = shell_exec ("".$CONF_OPENVAS_PATH_OMP." -u ".$CONF_OPENVAS_ADMIN_LOGIN." -w ".$CONF_OPENVAS_ADMIN_PASSWORD." -p 9393 --xml='<create_task><name>webissue".$issueId."</name><comment>test</comment><config id=\"".$CONF_OPENVAS_CONFIG_ID."\"/><target id=\"".$targetid."\"/><alert id=\"".$alertid."\"/></create_task>'");
		    preg_match('|<create_task_response id=\"([^"]*)\"|', $output, $matches);
		    $taskid = $matches[1];
		  }
		  
		  if(isset($taskid))
		  {
		    $output = shell_exec ("".$CONF_OPENVAS_PATH_OMP." -u ".$CONF_OPENVAS_ADMIN_LOGIN." -w ".$CONF_OPENVAS_ADMIN_PASSWORD." -p 9393 --xml='<start_task task_id=\"".$taskid."\"/>'");
		    preg_match('@<report_id>(.*)</report_id>.*@i', $output, $matches);
		    $reportid = $matches[1];
		  }
		    
		  if(isset($reportid))
		  {
		    $attribute = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID);
		    $value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $targetid );
		    $issueManager->setValue( $issue, $attribute, $value);
		    $attribute = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID);
		    $value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $taskid );
		    $issueManager->setValue( $issue, $attribute, $value );
		    $attribute = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID);
		    $value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $reportid );
		    $issueManager->setValue( $issue, $attribute, $value );
		    $attribute = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID);
		    $value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $targetid );
		    $issueManager->setValue( $issue, $attribute, $value );
		    
		    $attributetime = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME );
		    $valuetime = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], "in progress" );
		    $issueManager->setValue( $issue, $attributetime, $valuetime );
		  
		  }
		  else
		    $issueId = 0;
		} 
		}
		catch ( System_Api_Error $ex ) {
		  $this->logp( $ex );
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
	
	    $req["id_issue"] = $req["id_scan"];
	    $this->deleteissue($req);
	}
	
	function deleteserver($req){
	
	  $req["id_issue"] = $req["id_server"];
	  $this->deleteissue($req);
	  
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
		if(filter_var($req["ipsaddress"], FILTER_VALIDATE_IP))
		{
		  $folder = $projectManager->getFolder( $req["id_folder_servers"] );
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
	
	function addissue($req){
	  
	    $req = (array) $req;
	    $issueId = 0;
	  
	    if($this->authws())
	    {
	      $issueManager = new System_Api_IssueManager();
	      $projectManager = new System_Api_ProjectManager();
	      $typeManager = new System_Api_TypeManager();
	    
	      try {
		$folder = $projectManager->getFolder( $req["id_folder_bugs"] );
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
		
		foreach ( $rows as $idattribute => $attribute ) {
		  $value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$idattribute]] );
		  $issueManager->setValue( $issue, $attribute, $value );
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
	    $folderId1 = 1;
	    $folderId2 = 2;
	    $folderId3 = 3;
	    $folderId3 = 4;
	    
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
	    
	    
	    
