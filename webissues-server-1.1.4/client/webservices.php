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
	
	function addproject($req){
	  
	    $req = (array) $req;
	    $typeManager = new System_Api_TypeManager();
	    $projectManager = new System_Api_ProjectManager();
	    
	    $projectId = 0;
	    $folderId1 = 1;
	    $folderId2 = 2;
	    $folderId3 = 3;
        
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
		
		$folderId1 = $projectManager->addFolder( $project, $type, "Bugs" );
		$folderId2 = $projectManager->addFolder( $project, $type, "Servers" );
		$folderId3 = $projectManager->addFolder( $project, $type, "Codes" );
		
	    } catch ( System_Api_Error $ex ) {
		$this->logp( $ex );
	    }

	    $tab = array(
		array(
		'id_project' => $projectId,
		'id_folder_bugs' => $folderId1,
		'id_folder_servers' => $folderId2,
		'id_folder_codes' => $folderId3
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
	    
	    
	    
