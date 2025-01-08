/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets RDP login events (event ID 1149) from the Terminal Services Remote and    |
| local sessions (event IDs 21, 22, and 25) from the Local Session Manager event |
| logs where the source IP address comes from an external IP range. \"unknown\"  |
| results are given when the source IP address is within the IPv6 range.         |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
eventid,
CASE eventid
   WHEN 21 THEN eventid || ' - Session logon succeeded'
   WHEN 22 THEN eventid || ' - Shell start notification received'
   WHEN 25 THEN eventid || ' - Session reconnection successful'
   ELSE NULL
END AS description,
JSON_EXTRACT(data, '$.UserData.User') AS username,
SUBSTR(JSON_EXTRACT(data, '$.UserData.User'), 1, INSTR(JSON_EXTRACT(data, '$.UserData.User'), '\') - 1) AS domain,
JSON_EXTRACT(data, '$.UserData.Address') AS source_IP,
JSON_EXTRACT(data, '$.UserData.SessionID') AS session_ID,
CASE
    WHEN JSON_EXTRACT(data, '$.UserData.Address') GLOB '*[a-zA-Z]*' THEN 'private_IP'
    WHEN INSTR(JSON_EXTRACT(data, '$.UserData.Address'), '192.168.') = 1 THEN 'private_IP'  
    WHEN INSTR(JSON_EXTRACT(data, '$.UserData.Address'), '172.') = 1 AND CAST(SUBSTR(JSON_EXTRACT(data, '$.UserData.Address'), 5, 2) AS INTEGER) BETWEEN 16 AND 31 THEN 'private_IP'
    WHEN INSTR(JSON_EXTRACT(data, '$.UserData.Address'), '10.') = 1 THEN 'private_IP'
    WHEN INSTR(JSON_EXTRACT(data, '$.UserData.Address'), '127.') = 1 THEN 'private_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Address') = '0.0.0.0' THEN 'private_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Address') LIKE '%::%' THEN 'unknown'
    WHEN JSON_EXTRACT(data, '$.UserData.Address') = '' THEN 'private_IP'
   ELSE 'external_IP'
END AS status,
'TS LocalSession EVTX' AS data_source,
'Logins.01.4' AS query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    AND eventid IN (21,22,25)
    AND (status = 'external_IP' OR status = 'unknown')
    AND time > 0

UNION ALL

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
eventid,
CASE eventid
   WHEN 1149 THEN eventid || ' - User authentication succeeded'
   ELSE NULL
END AS description,
JSON_EXTRACT(data, '$.UserData.Param1') AS username,
JSON_EXTRACT(data, '$.UserData.Param2') AS domain,
JSON_EXTRACT(data, '$.UserData.Param3') AS source_IP,
NULL AS Session_ID,
CASE
    WHEN INSTR(JSON_EXTRACT(data, '$.UserData.Param3'), '192.168.') = 1 THEN 'private_IP'
    WHEN INSTR(JSON_EXTRACT(data, '$.UserData.Param3'), '172.') = 1 AND CAST(SUBSTR(JSON_EXTRACT(data, '$.UserData.Param3'), 5, 2) AS INTEGER) BETWEEN 16 AND 31 THEN 'private_IP'
    WHEN INSTR(JSON_EXTRACT(data, '$.UserData.Param3'), '10.') = 1 THEN 'private_IP'
    WHEN INSTR(JSON_EXTRACT(data, '$.UserData.Param3'), '127.') = 1 THEN 'private_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') = '0.0.0.0' THEN 'private_IP'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') LIKE '%::%' THEN 'unknown'
    WHEN JSON_EXTRACT(data, '$.UserData.Param3') = '' THEN 'private_IP'
    ELSE 'external_IP'
END AS status,
'TS RemoteConnection EVTX' AS data_source,
'Logins.01.4' AS query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    AND eventid = 1149
    AND (status = 'external_IP' OR status = 'unknown')
    AND time > 0
