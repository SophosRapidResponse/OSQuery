/******************************* Sophos.com/RapidResponse *******************************\
| DESCRIPTION                                                                            |
| The query identifies when the Windows event log was cleared. This is often done by TA  |
| in an attempt to evade detection or destroy forensic evidence on a system.             |
| The analyst needs to validate if the activity was a legitimate action taken by the     |
| account responsible for clearing the Windows logs.                                     |
|                                                                                        |
| REFERENCE:                                                                             |
| https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-1102|
| https://support.sophos.com/support/s/article/KB-000038860?language=en_US               |
|                                                                                        |
| Version: 1.0                                                                           |
| Author: The Rapid Response Team                                                        |
| github.com/SophosRapidResponse                                                         |
\*****************************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime) AS Datetime, 
    source AS Source,
    provider_name AS Provider_Name,
    eventid AS Event_ID,
    CASE 
    WHEN eventid = 1102 THEN 'The audit log was cleared'
    WHEN eventid = 104 THEN 'Event Log was Cleared '
    END AS Details,
    JSON_EXTRACT(data, '$.UserData.Channel') AS Channel,
    JSON_EXTRACT(data, '$.UserData.SubjectUserName') AS Account_Name,
    JSON_EXTRACT(data, '$.UserData.SubjectDomainName') AS Domain_Name,
    user_id AS SID,
    'EVTX' AS Data_Source,
    'T1070.001 - Windows Event Log Cleared' AS Query 
FROM sophos_windows_events
WHERE provider_name = 'Microsoft-Windows-Eventlog'
    AND (
    source LIKE 'System' OR
    source LIKE 'Security')
    AND eventid IN (104,1102)
ORDER BY datetime DESC