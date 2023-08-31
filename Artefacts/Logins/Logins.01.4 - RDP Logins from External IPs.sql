/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets all RDP login events (EID 1149,21,22,25)from Terminal Services Remote and |
| Local Session Connections in which the source IP is coming from an external IP |
| range. The query might output "unknown" when source ip is under the IPv6 range |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/techniques/T1021/001/                                 |
|                                                                                |
| Version: 1.0                                                                   |
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
'TS LocalSession' AS source,
JSON_EXTRACT(data, '$.UserData.User') AS username,
SUBSTR(JSON_EXTRACT(data, '$.UserData.User'), 1, INSTR(JSON_EXTRACT(data, '$.UserData.User'), '\') - 1) AS domain,
JSON_EXTRACT(data, '$.UserData.Address') AS source_IP,
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
'Logins.01.4' AS query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
    AND eventid IN (21,22,25)
    AND (status = 'external_IP' OR status = 'unknown')

UNION ALL

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
eventid,
CASE eventid
   WHEN 1149 THEN eventid || ' - User authentication succeeded'
   ELSE NULL
END AS description,
'TS RemoteConnection' AS source,
JSON_EXTRACT(data, '$.UserData.Param1') AS username,
JSON_EXTRACT(data, '$.UserData.Param2') AS domain,
JSON_EXTRACT(data, '$.UserData.Param3') AS source_IP,
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
'Logins.01.4' AS query
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
    AND eventid = 1149
    AND (status = 'external_IP' OR status = 'unknown')
