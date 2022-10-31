/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all instance of event ID 5861 from WMI-Activity/Operational. This event  |
| gets all permanent WMI event consumers which consist the primary means by      |
| which an adversary can achieve persistence using WMI.                          |
|                                                                                |
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
    'EVTX' AS Data_Source,
    'WMI Permanent Event Consumers' AS Query 
FROM sophos_windows_events
WHERE source = 'Microsoft-Windows-WMI-Activity/Operational' AND eventid = '5861'
ORDER BY datetime DESC