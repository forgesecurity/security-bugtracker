<?php
/**************************************************************************
* This file is part of the WebIssues Server program
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

class Client_SecurityPlugin extends System_Web_Component
{
    private $install_security = null;
    
    protected function __construct()
    {
        parent::__construct();
    }

    protected function execute()
    {
        $this->view->setDecoratorClass( 'Common_FixedBlock' );
        $this->view->setSlot( 'page_title', $this->tr( 'Security Plugin Configuration' ) );
        
	include( 'securityplugin.conf.php' );

	$typeManager = new System_Api_TypeManager();
	$projectManager = new System_Api_ProjectManager();
	$issueManager = new System_Api_IssueManager();
	
        $this->install_security = $this->request->getQueryString( 'install' );
        $this->alertscanid = $this->request->getQueryString( 'alertscanid' );
        
        if(!empty($this->alertscanid))
        {
	    try {
	      $issue = $issueManager->getIssue( $this->alertscanid );
	      $projectid = $issue["project_id"];
	      
	      $project = $projectManager->getProject( $issue["project_id"] );
	      $id_folder_scans = 0;
	      $folders = $projectManager->getFoldersForProject( $project );
	      foreach ( $folders as $idfolder => $folder ) {
		if($folder["type_id"] == $CONF_ID_TYPE_FOLDER_SCANS) // REMPLACER PAR TYPE FOLDER = SERVER
		{
		  $id_folder_scans = $folder["folder_id"];
		  break;
		}
	      }
	      
	      
	      } catch ( System_Api_Error $ex ) {
	      $this->logp( $ex );
	    }
        
        }

        if ( $this->install_security == "yes" ) { 
            
	    $id_type_folder_servers = $typeManager->addIssueType( "Servers" );
	    $id_type_folder_codes = $typeManager->addIssueType( "Codes" );
	    $id_type_folder_scans = $typeManager->addIssueType( "Scans" );
	
	    $type_folder_servers = $typeManager->getIssueType($id_type_folder_servers);
	    $type_folder_codes = $typeManager->getIssueType($id_type_folder_codes);
	    $type_folder_scans = $typeManager->getIssueType($id_type_folder_scans);
	    
	    
	    
	    /* ************************** FOLDER SERVERS ************************************** */
	    /*
	    $info1 = new System_Api_DefinitionInfo();
	    $info1->setType( 'TEXT' );
	    $info1->setMetadata( 'multi-line', 0 );
	    $info1->setMetadata( 'min-length', 1 );
	    $info1->setMetadata( 'max-length', 30 );
	    $info1->setMetadata( 'required', 1 );
	    $info1->setMetadata( 'default', "" );
	    */
	    $info1 = new System_Api_DefinitionInfo();
	    $info1->setType( 'ENUM' );
	    $info1->setMetadata( 'items', array('Développement', 'Qualification', 'Production') );
	    $info1->setMetadata( 'editable', 0 );
	    $info1->setMetadata( 'multi-select', 0 );
	    $info1->setMetadata( 'min-length', 1 );
	    $info1->setMetadata( 'max-length', 30 );
	    $info1->setMetadata( 'required', 1 );
	    $info1->setMetadata( 'default', "Production" );
	    
	    $info2 = new System_Api_DefinitionInfo();
	    $info2->setType( 'ENUM' );
	    $info2->setMetadata( 'items', array() );
	    $info2->setMetadata( 'editable', 1 );
	    $info2->setMetadata( 'multi-select', 0 );
	    $info2->setMetadata( 'min-length', 1 );
	    $info2->setMetadata( 'max-length', 30 );
	    $info2->setMetadata( 'required', 1 );
	    $info2->setMetadata( 'default', "" );
	    
	    //  $id_attribute_folder_hostname = $typeManager->addAttributeType( $type_folder_servers, "hostname", $info1->toString() );
	    $id_attribute_folder_servers_ipsaddress = $typeManager->addAttributeType( $type_folder_servers, "ips address", $info2->toString() );
	    $id_attribute_folder_servers_use = $typeManager->addAttributeType( $type_folder_servers, "use", $info1->toString() );
	    
	    $attributes_servers = $typeManager->getAttributeTypesForIssueType( $type_folder_servers );
	    foreach ( $attributes_servers as $attribute )
	      $columns[ System_Api_Column::UserDefined + $attribute[ 'attr_id' ] ] = $attribute[ 'attr_name' ];
            
            
	    $info = new System_Api_DefinitionInfo();
	    $info->setType( 'VIEW' );

	    $columns = array_keys( $columns );
	    $info->setMetadata( 'columns', "1,0,".implode( ',', $columns ) );
	    $info->setMetadata( 'sort-column', System_Api_Column::ID );
	    
	    $viewManager = new System_Api_ViewManager();
	    try {
		    $viewManager->setViewSetting( $type_folder_servers, 'default_view', $info->toString() );
	    } catch ( System_Api_Error $ex ) {
		$this->form->getErrorHelper()->handleError( 'viewName', $ex );
	    }
	    /**********************************************************************************/
	    
	    
	    
	    /* ************************** FOLDER SCANS ************************************** */
	    $info1 = new System_Api_DefinitionInfo();
	    $info1->setType( 'ENUM' );
	    $info1->setMetadata( 'items', array('openvas', 'dependency-check', 'openscat') );
	    $info1->setMetadata( 'editable', 0 );
	    $info1->setMetadata( 'multi-select', 0 );
	    $info1->setMetadata( 'min-length', 1 );
	    $info1->setMetadata( 'max-length', 30 );
	    $info1->setMetadata( 'required', 1 );
	    $info1->setMetadata( 'default', "openvas" );
	    
	    $info2 = new System_Api_DefinitionInfo();
	    $info2->setType( 'ENUM' );
	    $info2->setMetadata( 'items', array('stopped', 'in progress', 'finished') );
	    $info2->setMetadata( 'editable', 0 );
	    $info2->setMetadata( 'multi-select', 0 );
	    $info2->setMetadata( 'min-length', 1 );
	    $info2->setMetadata( 'max-length', 30 );
	    $info2->setMetadata( 'required', 1 );
	    $info2->setMetadata( 'default', "stopped" );
	   
	    $info3 = new System_Api_DefinitionInfo();
	    $info3->setType( 'ENUM' );
	    $info3->setMetadata( 'items', array('info', 'minor', 'medium', 'high') );
	    $info3->setMetadata( 'editable', 0 );
	    $info3->setMetadata( 'multi-select', 0 );
	    $info3->setMetadata( 'min-length', 1 );
	    $info3->setMetadata( 'max-length', 30 );
	    $info3->setMetadata( 'required', 1 );
	    $info3->setMetadata( 'default', "info" );
	    
	  //  $id_attribute_folder_hostname = $typeManager->addAttributeType( $type_folder_servers, "hostname", $info1->toString() );
	    $id_attribute_folder_scans_tool = $typeManager->addAttributeType( $type_folder_scans, "tool", $info1->toString() );
	    $id_attribute_folder_scans_time = $typeManager->addAttributeType( $type_folder_scans, "time", $info2->toString() );
	    $id_attribute_folder_scans_severity = $typeManager->addAttributeType( $type_folder_scans, "severity", $info3->toString() );
	    
	    $attributes_servers = $typeManager->getAttributeTypesForIssueType( $type_folder_scans );
	    foreach ( $attributes_servers as $attribute )
	      $columns[ System_Api_Column::UserDefined + $attribute[ 'attr_id' ] ] = $attribute[ 'attr_name' ];
            
            
	    $info = new System_Api_DefinitionInfo();
	    $info->setType( 'VIEW' );

	    $columns = array_keys( $columns );
	    $info->setMetadata( 'columns', "1,0,".implode( ',', $columns ) );
	    $info->setMetadata( 'sort-column', System_Api_Column::ID );
	    
	    $viewManager = new System_Api_ViewManager();
	    try {
		    $viewManager->setViewSetting( $type_folder_scans, 'default_view', $info->toString() );
	    } catch ( System_Api_Error $ex ) {
		$this->form->getErrorHelper()->handleError( 'viewName', $ex );
	    }
	    
	    
	    
	    $info1 = new System_Api_DefinitionInfo();
	    $info1->setType( 'TEXT' );
	    $info1->setMetadata( 'multi-line', 0 );
	    $info1->setMetadata( 'min-length', 1 );
	    $info1->setMetadata( 'max-length', 40 );
	    $info1->setMetadata( 'required', 0 );
	    $info1->setMetadata( 'default', "" );
	    
	    $id_attribute_folder_scans_targetid = $typeManager->addAttributeType( $type_folder_scans, "targetid", $info1->toString() );
	    
	    
	    $info2 = new System_Api_DefinitionInfo();
	    $info2->setType( 'TEXT' );
	    $info2->setMetadata( 'multi-line', 0 );
	    $info2->setMetadata( 'min-length', 1 );
	    $info2->setMetadata( 'max-length', 40 );
	    $info2->setMetadata( 'required', 0 );
	    $info2->setMetadata( 'default', "" );
	    
	    $id_attribute_folder_scans_tasktid = $typeManager->addAttributeType( $type_folder_scans, "tasktid", $info2->toString() );
	    
	    
	    $info3 = new System_Api_DefinitionInfo();
	    $info3->setType( 'TEXT' );
	    $info3->setMetadata( 'multi-line', 0 );
	    $info3->setMetadata( 'min-length', 1 );
	    $info3->setMetadata( 'max-length', 40 );
	    $info3->setMetadata( 'required', 0 );
	    $info3->setMetadata( 'default', "" );
	    
	    $id_attribute_folder_scans_reportid = $typeManager->addAttributeType( $type_folder_scans, "reportid", $info3->toString() );
	    
	    
	    $info4 = new System_Api_DefinitionInfo();
	    $info4->setType( 'TEXT' );
	    $info4->setMetadata( 'multi-line', 0 );
	    $info4->setMetadata( 'min-length', 1 );
	    $info4->setMetadata( 'max-length', 40 );
	    $info4->setMetadata( 'required', 0 );
	    $info4->setMetadata( 'default', "" );
	    
	    $id_attribute_folder_scans_alertid = $typeManager->addAttributeType( $type_folder_scans, "alertid", $info4->toString() );
	    
	    /**********************************************************************************/
            
            $fp = fopen("securityplugin.conf.php","w");
            fputs($fp,"<?php\n\n");
            //fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_HOSTNAME = $id_attribute_folder_hostname;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SERVERS_USE = $id_attribute_folder_servers_use;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SERVERS_IPSADDRESS = $id_attribute_folder_servers_ipsaddress;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_TOOL = $id_attribute_folder_scans_tool;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_TIME = $id_attribute_folder_scans_time;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_SEVERITY = $id_attribute_folder_scans_severity;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_TARGETID = $id_attribute_folder_scans_targetid;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_TASKID = $id_attribute_folder_scans_tasktid;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_REPORTID = $id_attribute_folder_scans_reportid;\n");
            fputs($fp,"\$CONF_ID_ATTRIBUTE_FOLDER_SCANS_ALERTID = $id_attribute_folder_scans_alertid;\n");
            fputs($fp,"\$CONF_ID_TYPE_FOLDER_SERVERS = $id_type_folder_servers;\n");
            fputs($fp,"\$CONF_ID_TYPE_FOLDER_CODES = $id_type_folder_codes;\n");
            fputs($fp,"\$CONF_ID_TYPE_FOLDER_SCANS = $id_type_folder_scans;\n\n");
            fputs($fp,"?>");
            fclose($fp);
        }
        
        elseif($this->install_security == "no" ) {
            
	    $type_folder_servers = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_SERVERS );
	    $type_folder_codes = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_CODES );
	    $type_folder_scans = $typeManager->getIssueType( $CONF_ID_TYPE_FOLDER_SCANS );
	      
	    $folders = $projectManager->getFoldersByIssueType( $type_folder_servers );
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
                
	      
	    $folders = $projectManager->getFoldersByIssueType( $type_folder_codes );
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
	      
	    $folders = $projectManager->getFoldersByIssueType( $type_folder_scans );
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
	    
	    $attributes_servers = $typeManager->getAttributeTypesForIssueType( $type_folder_servers );
	    foreach ( $attributes_servers as $attribute )
	      $typeManager->deleteAttributeType( $attribute );
	      
	    $attributes_codes = $typeManager->getAttributeTypesForIssueType( $type_folder_codes );
	    foreach ( $attributes_codes as $attribute )
	      $typeManager->deleteAttributeType( $attribute );
	      
	    $attributes_scans = $typeManager->getAttributeTypesForIssueType( $type_folder_scans );
	    foreach ( $attributes_scans as $attribute )
	      $typeManager->deleteAttributeType( $attribute );
        
	    $typeManager->deleteIssueType( $type_folder_servers, System_Api_TypeManager::ForceDelete );
	    $typeManager->deleteIssueType( $type_folder_codes, System_Api_TypeManager::ForceDelete );
	    $typeManager->deleteIssueType( $type_folder_scans, System_Api_TypeManager::ForceDelete );
        }

        $this->toolBar = new System_Web_ToolBar();

    }
}

System_Bootstrap::run( 'Common_Application', 'Client_SecurityPlugin' );