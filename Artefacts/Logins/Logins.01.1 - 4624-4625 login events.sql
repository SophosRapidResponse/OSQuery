/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Collect all 4624 and 4625 login events from the Security event log. This query |
| includes blank columns so data from this can be easily combined with the other |
| queries in this section with match the same format.                            |
|                                                                                |
| VARIABLES                                                                      |
| - username (type: username) = username to search for                           |
| - source_ip (type: IP address) = source IP user is logging in from             |
| - workstation (type: Device Name) = Computer on which the login was started    |
|                                                                                |
| TIP                                                                            |
| Use wildcards for each variable if you want to bring all users back.           |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
eventid AS EventID, 
CASE
   WHEN eventid = 4624 THEN eventid || ' - Successful Login' 
   WHEN eventid = 4625 THEN eventid || ' - Failed login' 
END AS Description, 
'Security' AS Source, 
JSON_EXTRACT(data, '$.EventData.TargetUserName') AS Target_User,
JSON_EXTRACT(data, '$.EventData.WorkstationName') AS Source_Machine_Network, 
JSON_EXTRACT(data, '$.EventData.IpAddress') AS Source_IP, 
JSON_EXTRACT(data, '$.EventData.ProcessName') AS Process_Name,
JSON_EXTRACT(data, '$.EventData.LogonType') AS Logon_Type, 
JSON_EXTRACT(data, '$.EventData.TargetUserSid') AS Target_User_SID,
JSON_EXTRACT(data, '$.EventData.Status') AS Logon_Status_Code,
JSON_EXTRACT(data, '$.EventData.TargetDomainName') AS Target_Domain_Name,
JSON_EXTRACT(data, '$.EventData.AuthenticationPackageName') AS Authentication_package,
NULL AS SessionID, 
NULL AS Session_ID,
'Security EVTX' AS Data_Source,
'Logins.01.1' AS Query 
FROM sophos_windows_events 
WHERE source = 'Security'
AND (eventid = 4624 OR eventid = 4625)
AND JSON_EXTRACT(data, '$.EventData.TargetUserName')  LIKE '$$username$$'
AND JSON_EXTRACT(data, '$.EventData.IpAddress') LIKE '$$source_ip$$'
AND JSON_EXTRACT(data, '$.EventData.WorkstationName') LIKE '$$workstation$$'
AND time > 0