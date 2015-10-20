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

	function logp($ex)
	{
	  $fp = fopen("webservices.log","a+");
	  fputs($fp, "log (".date('l jS \of F Y h:i:s A')."): $ex\n");
	  fclose($fp);
	}
	
	function adduser($req){
	
	  $id_user = 0;
	  $req = (array) $req;
	  
	  $userManager = new System_Api_UserManager();
	  try {
	      $id_user = $userManager->addUser( $req["login"], $req["username"], $req["password"], false );
	  } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
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
	  
	    $sessionManager = new System_Api_SessionManager();
	    try {
	      $sessionManager->login( "admin", "admin");
	    } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
	    }
	    
	    $issueManager = new System_Api_IssueManager();
	    $projectManager = new System_Api_ProjectManager();
	    $typeManager = new System_Api_TypeManager();
	    
	    try {
	      $folder = $projectManager->getFolder( $req["id_folder_scans"] );
	      $issueId = $issueManager->addIssue( $folder, $req["name"]);
	      $issue = $issueManager->getIssue( $issueId );
	      $issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );
	                
	      $parser = new System_Api_Parser();
	      $parser->setProjectId( $folder[ 'project_id' ] );
	      
	      include("securityplugin.conf.php");
		
	      $attributetime = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME );
	      $value = $parser->convertAttributeValue( $attributetime[ 'attr_def' ], $req["time"] );
              $issueManager->setValue( $issue, $attributetime, $value );
             
	      $attributetool = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_TOOL );
	      $value = $parser->convertAttributeValue( $attributetool[ 'attr_def' ], $req["tool"] );
              $issueManager->setValue( $issue, $attributetool, $value );
              
	      $attributeseve = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY );
	      $value = $parser->convertAttributeValue( $attributeseve[ 'attr_def' ], $req["severity"] );
              $issueManager->setValue( $issue, $attributeseve, $value );
	      
	      $project = $projectManager->getProject( $folder[ 'project_id' ] );
	      $id_folder_servers = 0;
	      $projects[0] = $project;
	      $folders = $projectManager->getFoldersForProjects( $projects );
	      foreach ( $folders as $folder ) 
	      {
	      $this->logp("dump : ".print_r($folder));
		    $this->logp( "idfolder = $idfolder and PROJECT ID = ".$folder['project_id']." and FOLDER ID =". $folder['type_id']. " and CONF ID = ".$CONF_ID_TYPE_FOLDER_SERVERS);
		if($folder["type_id"] == $CONF_ID_TYPE_FOLDER_SERVERS)
		{
		  $id_folder_servers = $folder["folder_id"];
		  break;
		}
	      }
	      
	      $nbips = 0;
	      $ipsaddress = array();
	      $folder = $projectManager->getFolder( $id_folder_servers );
	      $issues = $issueManager->getIssues($folder);
	      foreach ( $issues as $idissue => $bkpissue ) {
		$attributes = $issueManager->getAttributeValuesForIssue( $bkpissue );
		foreach ( $attributes as $idattribute => $attribute ) {
		  if($attribute["attr_id"] == $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS)
		  {
		    $ipsaddress[$nbips] = $attribute["attr_value"];
		    $nbips ++;
		    $this->logp( "IP ADDRESS FOUND =". $attribute["attr_value"]);
		  }
		}
	      }
	      
	      // vérifier le format de l'ip
	      if($nbips > 0)
	      {
		$this->logp( "START SCAN");
		$output = shell_exec ("omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<create_target><name>".$req["name"]."</name><hosts>".$ipsaddress[0]."</hosts></create_target>'");
		// <create_target_response id="c7217909-a7e6-4e97-976d-21d2537b6e3f" status_text="OK, resource created" status="201"></create_target_response>
		//preg_match("/<create_target_response id\=\\"([^\"]*)\\"/", $output);
		preg_match('|<create_target_response id=\"([^"]*)\"|', $output, $matches);
		$targetid = $matches[1];
		$this->logp( "TARGET OUTPUT =". $output);
		$this->logp( "TARGET ID =". $targetid);
		
		//$output = shell_exec ("omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<delete_target target_id=\"".$targetid."\"/>'");
		
		
		$output = shell_exec ("omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<create_alert><name>webissue".$issueId."</name><condition>Always</condition><event>Task run status changed<data>Done<name>status</name></data></event><method>HTTP Get<data><name>URL</name>http://localhost:8080/webissues-server-1.1.4/client/securityplugin.php?alertscanid=".$issueId."</data></method></create_alert>'");
		// <create_alert_response id="15b4873a-4952-4040-afb1-88db3410f83c" status_text="OK, resource created" status="201"></create_alert_response>
		preg_match('|<create_alert_response id=\"([^"]*)\"|', $output, $matches);
		$alertid = $matches[1];
		$this->logp( "ALERT OUTPUT =". $output);
		$this->logp( "ALERT ID =". $alertid);
		
		//$output = shell_exec ("omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<delete_alert alert_id="".$alertid.""/>'");
		//<delete_alert_response status_text="Alert is in use" status="400"></delete_alert_response>

		
		$output = shell_exec ("omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<create_task><name>".$req["name"]."</name><comment>test</comment><config id=\"a0e8fed8-45c1-4890-bd08-671257f63308\"/><target id=\"".$targetid."\"/><alert id=\"".$alertid."\"/></create_task>'");
		// <create_task_response id="cb144b4c-ef50-47f2-9403-81ac8fc7891f" status_text="OK, resource created" status="201"></create_task_response>
		preg_match('|<create_task_response id=\"([^"]*)\"|', $output, $matches);
		$taskid = $matches[1];
		$this->logp( "TASK OUTPUT =". $output);
		$this->logp( "TASK ID =". $taskid);
		
		//$output = shell_exec ("omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<delete_task task_id=\"".$taskid."\"/>'");
				
		
		
		$output = shell_exec ("omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<start_task task_id=\"".$taskid."\"/>'");
		// <start_task_response status_text="OK, request submitted" status="202"><report_id>a3db7806-b3c8-4551-b4d1-cc5c2b8ea0a6</report_id></start_task_response>
		preg_match('@<report_id>(.*)</report_id>.*@i', $output, $matches);
		$reportid = $matches[1];
		$this->logp( "REPORT OUTPUT =". $output);
		$this->logp( "REPORT ID =". $reportid);
		
		//$output = shell_exec ("omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<delete_report report_id=\"".$reportid."\"/>'");


            
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
		
		//$output = shell_exec ("omp --get-report ".$reportid." --format a994b278-1f62-11e1-96ac-406186ea4fc5 -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 > $reportid.xml");
	      }
	      
	      /*
	      linux-3ig5:~ # omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<create_target><name>test</name><hosts>127.0.0.1</hosts></create_target>'
<create_target_response id="c7217909-a7e6-4e97-976d-21d2537b6e3f" status_text="OK, resource created" status="201"></create_target_response>

linux-3ig5:~ # omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<delete_target target_id="c7217909-a7e6-4e97-976d-21d2537b6e3f"/>'
<delete_target_response status_text="OK" status="200"></delete_target_response>

linux-3ig5:~ # omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<create_task><name>test task</name><comment>test</comment><config id="a0e8fed8-45c1-4890-bd08-671257f63308"/><target id="15aff6dc-1cc2-40e5-a705-cefcec6bf71f"/></create_task>'
<create_task_response id="cb144b4c-ef50-47f2-9403-81ac8fc7891f" status_text="OK, resource created" status="201"></create_task_response>

linux-3ig5:~ # omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<delete_task task_id="cb144b4c-ef50-47f2-9403-81ac8fc7891f"/>'<delete_task_response status_text="OK" status="200"></delete_task_response>

linux-3ig5:~ # omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<start_task task_id="4b222d6f-1115-463b-8ea5-7c19058886c7"/>'<start_task_response status_text="OK, request submitted" status="202"><report_id>a3db7806-b3c8-4551-b4d1-cc5c2b8ea0a6</report_id></start_task_response>

linux-3ig5:~ # omp --get-tasks -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393
4b222d6f-1115-463b-8ea5-7c19058886c7  Done         test task

linux-3ig5:~ # omp -u admin -w 0825839c-0d3f-4417-a118-954a78e2553c -p 9393 --xml='<delete_report report_id="a3db7806-b3c8-4551-b4d1-cc5c2b8ea0a6"/>'
<delete_report_response status_text="OK" status="200"></delete_report_response>
*/

	      
	      
	    } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
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
	
	function addserver($req){
	  
	    $result = false;
	    $req = (array) $req;
	    $issueId = 0;
	  
	    $sessionManager = new System_Api_SessionManager();
	    try {
	      $sessionManager->login( "admin", "admin");
	    } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
	    }
	    
	    $issueManager = new System_Api_IssueManager();
	    $projectManager = new System_Api_ProjectManager();
	    $typeManager = new System_Api_TypeManager();
	    
	    try {
	      $folder = $projectManager->getFolder( $req["id_folder_servers"] );
	      $issueId = $issueManager->addIssue( $folder, $req["hostname"]);
	      $issue = $issueManager->getIssue( $issueId );
	      $issueManager->addDescription( $issue, $req["description"], System_Const::TextWithMarkup );
	         
	      $parser = new System_Api_Parser();
	      $parser->setProjectId( $folder[ 'project_id' ] );
	      
	      include("securityplugin.conf.php");

	      $attributeips = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS );
	      $value = $parser->convertAttributeValue( $attributeips[ 'attr_def' ], $req["ipsaddress"] );
              $issueManager->setValue( $issue, $attributeips, $value );
             
	      $attributeuse = $typeManager->getAttributeTypeForIssue( $issue, $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE );
	      $value = $parser->convertAttributeValue( $attributeuse[ 'attr_def' ], $req["use"] );
              $issueManager->setValue( $issue, $attributeuse, $value );
              
	    } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
	    }
	        
	    $tab = array(
		array(
		'id_server' => $issueId
		)
	    );
        
	    return $tab;
	}
	
	
	function deleteserver($req){
	
		$req["id_issue"] = $req["id_server"];
		$this->deleteissue($req);
	}
	
	
	function addissue($req){
	  
	    $result = false;
	    $req = (array) $req;
	    $issueId = 0;
	  
	    $sessionManager = new System_Api_SessionManager();
	    try {
	      $sessionManager->login( "admin", "admin");
	    } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
	    }
	    
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
	  
	    $sessionManager = new System_Api_SessionManager();
	    try {
	      $sessionManager->login( "admin", "admin");
	    } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
	    }
	    
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
	        
	    $tab = array(
		array(
		'result' => $result
		)
	    );
        
	    return $tab;
	}
	
	function deleteissue($req){
	
	    $result = false;
	    $req = (array) $req;
	    $issueManager = new System_Api_IssueManager();
      
	    $sessionManager = new System_Api_SessionManager();
	    try {
		$sessionManager->login( "admin", "admin");
	    } catch ( System_Api_Error $ex ) {
		$this->logp( $ex );
	    }
		
	    try 
	    {
		$issue = $issueManager->getIssue( $req["id_issue"] );
		$desc = $issueManager->getDescription( $issue );
                $issueManager->deleteIssue( $issue );
                $issueManager->deleteDescription( $descr );
		$result = true;
	    } catch ( System_Api_Error $ex ) {
		$this->logp( $ex );
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
	  $projectManager = new System_Api_ProjectManager();
	  
	  $sessionManager = new System_Api_SessionManager();
	  try {
	    $sessionManager->login( "admin", "admin");
	  } catch ( System_Api_Error $ex ) {
	    $this->logp( $ex );
	  }
		
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
	  $projectManager = new System_Api_ProjectManager();
	  
	  $sessionManager = new System_Api_SessionManager();
	  try {
	    $sessionManager->login( "admin", "admin");
	  } catch ( System_Api_Error $ex ) {
	    $this->logp( $ex );
	  }
		
	  $userManager = new System_Api_UserManager();
	  
	  try {
	    $user = $userManager->getUser( $req["id_user"] );
	    $project = $projectManager->getProject( $req["id_project"]);
	    $userManager->grantMember( $user, $project, System_Const::NoAccess );
	    $result = true;
	    } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
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
	    $projectManager = new System_Api_ProjectManager();
	    $issueManager = new System_Api_IssueManager();
       
	    try {
		$sessionManager = new System_Api_SessionManager();
		try {
		    $sessionManager->login( "admin", "admin");
		} catch ( System_Api_Error $ex ) {
			$this->logp( $ex );
		}
		
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
	    $typeManager = new System_Api_TypeManager();
	    $projectManager = new System_Api_ProjectManager();
        
	    try {
	    
		$principal = System_Api_Principal::getCurrent();        
		$sessionManager = new System_Api_SessionManager();
		try {
		    $sessionManager->login( "admin", "admin");
		} catch ( System_Api_Error $ex ) {
			$this->logp( $ex );
		}

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

	    $tab = array(
		array(
		'result' => $result
		)
	    );
	    
	    return $tab;
	}
	
	function addproject($req){
	  
	    $req = (array) $req;
	    $typeManager = new System_Api_TypeManager();
	    $projectManager = new System_Api_ProjectManager();
	    
	    $projectId = 0;
	    $folderId1 = 1;
	    $folderId2 = 2;
	    $folderId3 = 3;
	    $folderId3 = 4;
        
	    try {
	    
		/*
		<select name="issueType" id="field-projects-issueType" style="width: 15em;">
		<option value="2">Bugs</option>
		<option value="1">Forum</option>
		<option value="3">Tâches</option>
		*/
		
		$principal = System_Api_Principal::getCurrent();        
		$sessionManager = new System_Api_SessionManager();
		try {
		    $sessionManager->login( "admin", "admin");
		} catch ( System_Api_Error $ex ) {
			$this->logp( $ex );
		}
	    
		$type = $typeManager->getIssueType(2);
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
	    
	    
	    
