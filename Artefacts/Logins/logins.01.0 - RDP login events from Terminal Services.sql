/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This query collects all RDP login events (event ID 1149) from the Terminal     |
| Services Remote Connection Manager. It includes blank columns so the data can  |
| be easily combined with the other queries in this section that match the same  |
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
    WHEN eventid = 1149 THEN eventid || ' - User authentication succeeded' 
END AS Description, 
'TS Remote' AS Source, 
JSON_EXTRACT(data, '$.UserData.Param1') AS Username, 
JSON_EXTRACT(data, '$.UserData.Param2') AS Source_Machine_Network, 
JSON_EXTRACT(data, '$.UserData.Param3') AS Source_IP, 
NULL AS Process_Name, 
NULL AS Logon_Type, 
NULL AS User_SID, 
NULL AS Logon_Status_Code,
NULL AS Target_Domain_Name,
NULL AS Authentication_package,
NULL AS SessionID, 
NULL AS Session_ID,
'TS Remote Connection EVTX' AS Data_Source,
'Logins.01.0' AS Query 
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational' 
AND eventid = 1149 
AND JSON_EXTRACT(data, '$.UserData.Param1') LIKE '$$username$$' 
AND JSON_EXTRACT(data, '$.UserData.Param3') LIKE '$$source_ip$$'
AND time > 0