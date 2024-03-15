/******************************* Sophos.com/RapidResponse *******************************\
| DESCRIPTION                                                                            |
| List events that indicate Windows event logs have been cleared. It looks for EID 104   |
| and 1102 in the System and Security event logs. TACTIC: Defense Evasion                |
|                                                                                        |
| REFERENCE:                                                                             |
| https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102|
| https://support.sophos.com/support/s/article/KB-000038860?language=en_US               |
|                                                                                        |
| Query Type: Endpoint                                                                   |
| Version: 1.0                                                                           |
| Author: The Rapid Response Team                                                        |
| github.com/SophosRapidResponse                                                         |
\****************************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ', datetime) AS date_time,
source,
provider_name,
eventid,
CASE 
    WHEN eventid = 1102 THEN 'The audit log was cleared'
    WHEN eventid = 104 THEN 'Event Log was Cleared '
END AS details,
JSON_EXTRACT(data, '$.UserData.Channel') AS channel,
JSON_EXTRACT(data, '$.UserData.SubjectUserName') AS account_name,
JSON_EXTRACT(data, '$.UserData.SubjectDomainName') AS domain_name,
user_id AS SID,
'EVTX' AS data_source,
'EVTX.02.0' AS query
FROM sophos_windows_events
WHERE provider_name = 'Microsoft-Windows-Eventlog'
    AND (
    source LIKE 'System' OR
    source LIKE 'Security')
    AND eventid IN (104,1102)
    AND time > 0
ORDER BY datetime DESC