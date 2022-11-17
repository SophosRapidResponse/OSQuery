/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all events associated with service failures and crashes from System logs |
| Analysts can search for a specific service by providing a value to the variable|
| (ioc) otherwise the wildcard (%) can be used to bring all information          |
|                                                                                |
| VARIABLE                                                                       |
| - ioc (type: string)                                                           |
| - start_time (type: DATE)                                                      |
| - end_time (type: DATE)                                                        |
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
    CASE 
    WHEN eventid = 7022 THEN 'The service hung on starting'
    WHEN eventid = 7023 THEN 'The service terminated with the following error'
    WHEN eventid = 7024 THEN 'The service terminated with the following error'
    WHEN eventid = 7026 THEN 'The following boot-start or system-start driver(s) failed to load'
    WHEN eventid = 7026 THEN 'The service terminated unexpectedly. It has done this: ' || JSON_EXTRACT(data,'$.EventData.param3') || 'time(s)'|| 'The following corrective action will be taken in '|| JSON_EXTRACT(data,'$.EventData.param3') || ' milliseconds'
    WHEN eventid = 7034 THEN 'Service crashed unexpectedly'
    ELSE '-' END AS details,
    JSON_EXTRACT(data,'$.EventData.param1') as service_name,
    JSON_EXTRACT(data,'$.EventData.param2') as error_id,
    data as raw,
    'Services - Failures and Crashes' AS query,
    'EVTX' AS data_source
FROM sophos_windows_events
WHERE source = 'System' AND eventid IN ('7022','7023','7024','7026','7034')
AND raw LIKE '$$ioc$$'
AND time >= $$start_time$$
AND time <= $$end_time$$
ORDER BY date_time DESC