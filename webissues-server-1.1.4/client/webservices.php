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
	    
	      $type = $typeManager->getIssueTypeForFolder( $folder );
	      $rows = $typeManager->getAttributeTypesForIssueType( $type );
	      $viewManager = new System_Api_ViewManager();
	      $rows = $viewManager->sortByAttributeOrder( $type, $rows );
                        
	      $parser = new System_Api_Parser();
	      $parser->setProjectId( $folder[ 'project_id' ] );
         
	      $name_ws[0] = "time";
	      $name_ws[1] = "tool";
	      
	      foreach ( $rows as $idattribute => $attribute ) {
                $value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$idattribute]] );
                $issueManager->setValue( $issue, $attribute, $value );
	      }
	      
	      $project = $projectManager->getProject( $folder[ 'project_id' ] );
	      $folder = $projectManager->getFolder( $req["id_folder_scans"] );
	      $id_folder_servers = 0;
	      $folders = $projectManager->getFoldersForProject( $project );
	      foreach ( $folders as $idfolder => $folder ) {
		if($folder["folder_name"] == "Servers")
		{
		  $id_folder_servers = $folder["folder_id"];
		  break;
		}
	      }
	      
	      include("securityplugin.conf.php");
	      
	      $folder = $projectManager->getFolder( $id_folder_servers );
	      $issues = $issueManager->getIssues($folder);
	      foreach ( $issues as $idissue => $issue ) {
		$attributes = $issueManager->getAttributeValuesForIssue( $issue );
		foreach ( $attributes as $idattribute => $attribute ) {
		  if($attribute["attr_id"] == $CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS)
		  {
		    $this->logp( "IP ADDRESS FOUND =". $attribute["attr_value"]);
		  }
		}
	      }
	      
	      
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
	    
	      $type = $typeManager->getIssueTypeForFolder( $folder );
	      $rows = $typeManager->getAttributeTypesForIssueType( $type );
	      $viewManager = new System_Api_ViewManager();
	      $rows = $viewManager->sortByAttributeOrder( $type, $rows );
                        
	      $parser = new System_Api_Parser();
	      $parser->setProjectId( $folder[ 'project_id' ] );
         
	      $name_ws[0] = "ipsaddress";
	      $name_ws[1] = "use";
	      
	      foreach ( $rows as $idattribute => $attribute ) {
                $value = $parser->convertAttributeValue( $attribute[ 'attr_def' ], $req[$name_ws[$idattribute]] );
                $issueManager->setValue( $issue, $attribute, $value );
	      }
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
	    
	    
	    
