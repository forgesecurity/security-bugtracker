Security-bugtracker is a tool based on :
- webissues bug tracker : http://webissues.mimec.org/
- openvas security scanner : http://www.openvas.org/
- dependency check : https://github.com/jeremylong/DependencyCheck

the mainly additions to webissues are using webservices to launch security test tools and track linked bugs.

 - add a project :
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v1="http://securitybugtracker/V1">
   <soapenv:Header/>
   <soapenv:Body>
      <v1:addproject>
         <name>TEST</name>
         <description>TEST DESC</description>
      </v1:addproject>
   </soapenv:Body>
</soapenv:Envelope>
```
```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://securitybugtracker/V1">
   <SOAP-ENV:Body>
      <ns1:addproject_Response>
         <id_details>
            <id_project>27</id_project>
            <id_folder_bugs>73</id_folder_bugs>
            <id_folder_servers>74</id_folder_servers>
            <id_folder_codes>75</id_folder_codes>
            <id_folder_scans>76</id_folder_scans>
         </id_details>
      </ns1:addproject_Response>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```
 - add a server :
```xml
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v1="http://securitybugtracker/V1">
   <soapenv:Header/>
   <soapenv:Body>
      <v1:addserver>
         <id_folder_servers>74</id_folder_servers>
         <hostname>test</hostname>
         <description>test</description>
         <use>Développement</use>
         <ipsaddress>127.0.0.1</ipsaddress>
      </v1:addserver>
   </soapenv:Body>
</soapenv:Envelope>
```
```xml
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://securitybugtracker/V1">
   <SOAP-ENV:Body>
      <ns1:addserver_Response>
         <result_addserver_details>
            <id_server>1150</id_server>
         </result_addserver_details>
      </ns1:addserver_Response>
   </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

- is a tool in development for learning static analysis of source code, currently, you can for example, computing and printing :
- the Abstract Syntax Tree of a small program : 

![ScreenShot](https://raw.githubusercontent.com/eric-therond/accassias/master/documentation/ast_example1.png)

- the Control Flow Graph : 

![ScreenShot](https://raw.githubusercontent.com/eric-therond/accassias/master/documentation/cfg_example1.png)

- the generated machine code :

![ScreenShot](https://raw.githubusercontent.com/eric-therond/accassias/master/documentation/code_example1.png)

For more explanations, you can read user and developer manuals :
- https://github.com/eric-therond/accassias/blob/master/documentation/user_manual.pdf
- https://github.com/eric-therond/accassias/blob/master/documentation/developer_manual.pdf


