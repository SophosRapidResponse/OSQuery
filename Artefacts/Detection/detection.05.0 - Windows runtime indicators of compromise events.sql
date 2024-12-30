/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all events from the Sophos Runtime Indicators of Compromise journal      |
| within a specified time range.                                                 |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type: Date)                                                      |
| - end_time   (type: Date)                                                      |
| - username   (type: Username)                                                  |
| - sid        (type: String )                                                   |
| - sophos_pid (type: SophosPID)                                                 |
| - value      (type: String)                                                    |
|                                                                                |
| If opt for bringing all the data, a wildcard (%) can be used in the variables: |
| username, sid, sophos_pid, filename                                            |
|                                                                                |
| SEARCH EXAMPLES:                                                               |
| filename = %malware.exe%                                                       |
| sophos_pid = %6796:133107552746352584%                                         |
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
ioc.sophos_pid,
ioc.path,
ioc.sid,
CAST(u.username AS TEXT) AS user_name,
ioc.events AS raw_data,
'runtime ioc journal' AS data_source,
'detection.05.0' AS query
FROM sophos_runtime_ioc_journal AS ioc
INNER JOIN JSON_EACH(ioc.mitre_ttps) AS ttp
LEFT JOIN users AS u ON ioc.sid = u.uuid
WHERE
    ioc.time >= '$$start_time$$'
    AND ioc.time <= '$$end_time$$'
    AND u.username LIKE '$$username$$'
    AND ioc.sid LIKE '$$user_sid$$'
    AND ioc.sophos_pid LIKE '$$sophos_pid$$'
    AND ioc.events LIKE '$$value$$'
GROUP BY ioc.time