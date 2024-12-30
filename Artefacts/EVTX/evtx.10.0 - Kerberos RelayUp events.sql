/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Searches the Security event logs for successful logins potentially associated  |
| with the Kerberos RelayUp attack. The query also gets Process Journals for     |
| evidence of Kerberos RelayUp tool usage within a specified time range.         |
|                                                                                |
| VARIABLE:                                                                      |
| - start_time: (Type: DATE)                                                     |
| - end_time: (Type: DATE)                                                       |
|                                                                                |
| REFERENCE:                                                                     |
| https://github.com/Dec0ne/KrbRelayUp                                           |
| https://github.com/cube0x0/KrbRelay                                            |
| https://attack.mitre.org/techniques/T1558/003/                                 |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH evtx_data AS (
    SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
    source,
    provider_name,
    eventid,
    JSON_EXTRACT(data, '$.EventData.AuthenticationPackageName') AS AuthenticationPackageName,
    JSON_EXTRACT(data, '$.EventData.LogonType') AS LogonType,
    JSON_EXTRACT(data, '$.EventData.IpAddress') AS SourceIP,
    JSON_EXTRACT(data, '$.EventData.TargetUserSid') AS TargetUserSid,
    NULL AS process_name,
    NULL AS cmd_line,
    NULL AS sophos_pid,
    NULL AS process_start_time,
    NULL AS process_end_time,
    NULL AS username,
    NULL AS sid,
    NULL AS parent_sophos_pid,
    'EVTX' AS data_source,
    'EVTX.10.0' AS query
FROM sophos_windows_events
WHERE source = 'Security'
    AND eventid = 4624
    AND AuthenticationPackageName = 'Kerberos'
    AND LogonType = '3'
    AND SourceIP = '127.0.0.1'
    AND TargetUserSid LIKE 'S-1-5-21-%-500'
    AND time > 0
),

process_journal_data AS (
    SELECT 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
    NULL AS source,
    NULL AS provider_name,
    NULL AS eventid,
    NULL AS AuthenticationPackageName,
    NULL AS LogonType,
    NULL AS SourceIP, 
    NULL AS TargetUserSid,
    CAST (spj.process_name AS TEXT) process_name,
    spj.cmd_line,
    spj.sophos_pid,  
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
    CASE 
        WHEN spj.end_time = 0 THEN '' 
        ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) 
    END AS process_end_time, 
    users.username,
    spj.sid,
    spj.parent_sophos_pid, 
    'Process Journal' AS data_source,
    'EVTX.10.0' AS query 
FROM sophos_process_journal spj 
LEFT JOIN users ON spj.sid = users.uuid
WHERE LOWER(spj.process_name) IN ('cmd.exe', 'powershell.exe')
    AND spj.cmd_line LIKE '%krbrelayup%'
    AND spj.time >= $$start_time$$ 
    AND spj.time <= $$end_time$$
)

SELECT * FROM evtx_data
UNION ALL
SELECT * FROM process_journal_data