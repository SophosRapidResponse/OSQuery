/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all Windows runtime detections                                           |
|                                                                                |
| The user can search for a specific IOC: pid, process name, filename, IPs, hash,|
| SID, tasknames, GUID among others or can opt for collecting everything in the  |
| journals using the wildcard (%)                                                |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type: DATE)                                                      |
| - end_time   (type: DATE)                                                      |
| - ioc (type: STRING)                                                           |
|                                                                                |
| EXAMPLES:                                                                      |
| ioc = %malware.exe%                                                            |
| ioc = %6796:133107552746352584%                                                |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(ioc.time, 'unixepoch')) AS date_time,
    CASE WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0043' THEN 'Reconnaissance'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0042' THEN 'Resource Development'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0001' THEN 'Initial Access'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0002' THEN 'Execution'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0003' THEN 'Persistence'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0004' THEN 'Privilege Escalation'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0005' THEN 'Defense Evasion'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0006' THEN 'Credential Access'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0007' THEN 'Discovery'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0008' THEN 'Lateral Movement'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0009' THEN 'Collection'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0011' THEN 'Command and Control'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0010' THEN 'Exfiltration'
    WHEN CAST(JSON_EXTRACT(ttp.value, '$.tactic') AS TEXT) = 'TA0040' THEN 'Impact'
    END AS tactic,
    CAST(JSON_EXTRACT(ttp.value, '$.technique') AS TEXT) AS technique_id,
    ioc.threat_source,
    CAST(JSON_EXTRACT(event.value, '$.type') AS TEXT) indicator_type,
    ioc.sophos_pid,
    u.username,
    ioc.sid,
    ioc.events AS raw_data,
    'Runtime Journals/Users' AS source,
    'Runtime IOC Events - Windows' As query,
FROM sophos_runtime_ioc_journal AS ioc
JOIN JSON_EACH(ioc.mitre_ttps) AS ttp
JOIN JSON_EACH(ioc.events) AS event
LEFT JOIN users AS u ON ioc.sid = u.uuid
WHERE
    ioc.time >= $$start_time$$
    AND ioc.time <= $$end_time$$
    AND ioc.events LIKE '$$ioc$$'
GROUP BY ioc.sophos_pid, indicator_type
ORDER BY date_time DESC