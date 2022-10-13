/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets all data from Runtime Indicators of Compromise Journals                   |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type: DATE)                                                      |
| - end_time   (type: DATE)                                                      |
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
    CAST(JSON_EXTRACT(ttp.value, '$.technique') AS TEXT) AS technique,
    ioc.threat_source,
    CAST(JSON_EXTRACT(event.value, '$.type') AS TEXT) indicator_type,
    ioc.sophos_pid,
    ioc.path,
    u.username,
    ioc.sid,
    CAST(JSON_EXTRACT(event.value, '$.imagepath') AS TEXT) image_path,
    CAST(JSON_EXTRACT(event.value, '$.cmdline') AS TEXT) cmd_line,
    CAST(JSON_EXTRACT(event.value, '$.regPath') AS TEXT) regPath,
    CAST(JSON_EXTRACT(event.value, '$.valueName') AS TEXT) regValueName,
    CAST(JSON_EXTRACT(ttp.value, '$.verbosity') AS INTEGER) verbosity,
    ioc.events AS raw_data,
    'Mitre - Runtime IOC Events' As Query
FROM sophos_runtime_ioc_journal AS ioc
JOIN JSON_EACH(ioc.mitre_ttps) AS ttp
JOIN JSON_EACH(ioc.events) AS event
LEFT JOIN users AS u ON ioc.sid = u.uuid
WHERE
    ioc.time >= $$start_time$$
    AND ioc.time <= $$end_time$$
GROUP BY ioc.sophos_pid
ORDER BY date_time DESC


