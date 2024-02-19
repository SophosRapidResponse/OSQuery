/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query lists all service associated with SWO2 application. If the service is|
| related to WSO2 Identity Server product it will also output if the application |
| is vulnerable to CVE-2022-29464                                                |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
CASE
WHEN path LIKE ('%wso2is-5.7.0%') THEN 'vulnerable'
WHEN path LIKE ('%wso2is-5.2.0%') THEN 'vulnerable'
WHEN path LIKE ('%wso2is-5.4.1%') THEN 'vulnerable'
WHEN path LIKE ('%wso2is-5.5.0%') THEN 'vulnerable'
WHEN path LIKE ('%wso2is-5.6.0%') THEN 'vulnerable'
WHEN path LIKE ('%wso2is-5.10.0%') THEN 'vulnerable'
WHEN path LIKE ('%wso2is-5.9.0%') THEN 'vulnerable'
WHEN path LIKE ('%wso2is-5.11.0%') THEN 'vulnerable'
ELSE 'unknown' END AS is_Vulnerable,
regex_match(path,'Dwrapper.working.dir=.*"',0) As Working_Directory,
name As Name, 
service_type As Service_type,
display_name As Display_name,
status As Status, 
start_type As Start_time,
path As Path,
module_path As Module_path,
description As Description,
user_account As User_account,
'Services' AS Data_Source,
'WSO2 Services' AS Query
FROM services 
WHERE name LIKE '%WSO2%' OR display_name LIKE '%Ellucian%'