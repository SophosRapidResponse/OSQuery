/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Collects all event ID 1149, 4624, 4625, and 21-40 login events from Terminal   |
| Services Local, Terminal Services Remote, and Security event logs.             |
|                                                                                |
| VARIABLES                                                                      |
| username(username) = username to search for                                    |
| source_ip(IP address) = source IP user is logging in from                      |
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
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime, 
eventid AS EventID, 
CASE WHEN eventid = 1149 THEN eventid || ' - User authentication succeeded' END AS Description, 
'TS Remote' AS Source, 
JSON_EXTRACT(data, '$.UserData.Param1') AS Username, 
JSON_EXTRACT(data, '$.UserData.Param2') AS Source_Machine_Network, 
JSON_EXTRACT(data, '$.UserData.Param3') AS Source_IP, 
NULL AS Process_Name, 
NULL AS Logon_Type, 
NULL AS User_SID, 
NULL AS Authentication_package,
NULL AS SessionID, 
NULL AS Session_ID,
'TS Remote Connection EVTX' AS Data_Source,
'Logins.01.3' AS Query 
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' 
AND eventid = 1149 
AND JSON_EXTRACT(data, '$.UserData.Param1') LIKE '$$username$$' 
AND JSON_EXTRACT(data, '$.UserData.Param3') LIKE '$$source_ip$$'
AND time > 0

UNION ALL

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime, 
eventid AS EventID,  
CASE   
   WHEN eventid = 21 THEN eventid || ' - Logon succeeded' 
   WHEN eventid = 22 THEN eventid || ' - Shell start' 
   WHEN eventid = 23 THEN eventid || ' - Logoff succeeded' 
   WHEN eventid = 24 THEN eventid || ' - Session disconnected' 
   WHEN eventid = 25 THEN eventid || ' - Reconnection succeeded' 
   WHEN eventid = 39 THEN eventid || ' - Disconnected by another session' 
   WHEN eventid = 40 THEN eventid || ' - Disconnect/Reconnect' 
   ELSE eventid || ' - Unknown' 
END AS Description, 
'TS Local' AS Source, 
JSON_EXTRACT(data, '$.UserData.User') AS Username, 
NULL AS Source_Machine_Network, 
JSON_EXTRACT(data, '$.UserData.Address') AS Source_IP, 
NULL AS Process_Name, 
NULL AS Logon_Type, 
NULL AS User_SID, 
NULL AS Authentication_package,
JSON_EXTRACT(data, '$.UserData.Session') AS SessionID, 
JSON_EXTRACT(data, '$.UserData.SessionID') AS Session_ID,
'TS Local Session EVTX' AS Data_Source,
'Logins.01.3' AS Query 
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
AND JSON_EXTRACT(data, '$.UserData.User') LIKE '$$username$$' 
AND JSON_EXTRACT(data, '$.UserData.Address') LIKE '$$source_ip$$' 
AND time > 0

UNION ALL

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime, 
eventid AS EventID, 
CASE
   WHEN eventid = 4624 THEN eventid || ' - Successful Login' 
   WHEN eventid = 4625 THEN eventid || ' - Failed login' 
END AS Description, 
'Security' AS Source, 
JSON_EXTRACT(data, '$.EventData.TargetUserName') AS Username, 
JSON_EXTRACT(data, '$.EventData.WorkstationName') AS Source_Machine_Network, 
JSON_EXTRACT(data, '$.EventData.IpAddress') AS Source_IP, 
JSON_EXTRACT(data, '$.EventData.ProcessName') AS Process_Name, 
JSON_EXTRACT(data, '$.EventData.LogonType') AS Logon_Type, 
JSON_EXTRACT(data, '$.EventData.TargetUserSid') AS User_SID, 
JSON_EXTRACT(data, '$.EventData.AuthenticationPackageName') AS Authentication_package,
NULL AS SessionID, 
NULL AS Session_ID,
'Security EVTX' AS Data_Source,
'Logins.01.3' AS Query 
FROM sophos_windows_events 
WHERE source = 'Security'
AND (eventid = 4624 OR eventid = 4625)
AND JSON_EXTRACT(data, '$.EventData.TargetUserName')  LIKE '$$username$$' 
AND JSON_EXTRACT(data, '$.EventData.IpAddress') LIKE '$$source_ip$$'
AND time > 0