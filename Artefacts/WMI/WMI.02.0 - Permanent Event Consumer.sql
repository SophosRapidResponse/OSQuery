/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets all event ID 5861 from WMI-Activity/Operational logs. This event records  |
| all permanent WMI event consumers installed on the host. Useful to find WMI    |
| persistance. TACTIC: Persistence"                                              |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time, 
    source,
    provider_name,
    eventid,
    JSON_EXTRACT(data,'$.UserData.CONSUMER') AS consumer,
    JSON_EXTRACT(data,'$.UserData.ESS') AS ess,
    JSON_EXTRACT(data,'$.UserData.Namespace') AS namespace,
    JSON_EXTRACT(data,'$.UserData.Operation_ESStoConsumerBinding') AS binding,
    JSON_EXTRACT(data,'$.UserData.PossibleCause') AS cause,
    'EVTX' AS data_source,
    'WMI.02.0' AS query 
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-WMI-Activity/Operational' 
AND eventid = '5861'
AND time > 0
ORDER BY datetime DESC