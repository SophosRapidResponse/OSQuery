/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This query collects all RDP login events (event IDs 21 - 40) from Terminal     |
| Services Local Session Manager. It includes blank columns so the data can be   |
| easily combined with the other queries in this section that match the same     |
| format.                                                                        |
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
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
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
NULL AS Logon_Status_Code,
NULL AS Target_Domain_Name,
NULL AS Authentication_package,
JSON_EXTRACT(data, '$.UserData.Session') AS SessionID, 
JSON_EXTRACT(data, '$.UserData.SessionID') AS Session_ID,
'TS Local Session EVTX' AS Data_Source,
'Logins.01.2' AS Query 
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
AND JSON_EXTRACT(data, '$.UserData.User') LIKE '$$username$$' 
AND JSON_EXTRACT(data, '$.UserData.Address') LIKE '$$source_ip$$' 
AND time > 0
ORDER BY time DESC