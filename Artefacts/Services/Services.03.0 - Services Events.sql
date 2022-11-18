/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look for services being installed, started/stopped, changed, or crashed via the|
| System event log and event IDs: 7034, 7035, 7036, 7040, 7045                   |
|                                                                                |
| Services logs should be investigated around the time of a suspected compromise |
| Services started on boot illustrate persistence. Services can crash due to     |
| attacks like process injection.                                                |
|                                                                                |
| VARIABLES                                                                      |
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
    eventid,
    CASE 
    WHEN eventid = 7034 THEN 'Service crashed unexpectedly'
    WHEN eventid = 7035 THEN 'Service sent a Start/Stop control'
    WHEN eventid = 7036 THEN 'Service started or stopped'
    WHEN eventid = 7040 THEN 'Start type changed'
    WHEN eventid = 7045 THEN 'A service was installed on the system' 
    END as details,
    CAST(JSON_EXTRACT(data, '$.EventData.AccountName') AS TEXT) AS account_name,
    CASE WHEN eventid = 7045 THEN CAST(JSON_EXTRACT(data, '$.EventData.ServiceName') AS TEXT)
    WHEN eventid = 7040 THEN CAST(JSON_EXTRACT(data, '$.EventData.param4') AS TEXT)
    WHEN eventid = 7034 THEN CAST(JSON_EXTRACT(data, '$.EventData.param1') AS TEXT)
    WHEN eventid = 7036 THEN CAST(JSON_EXTRACT(data, '$.EventData.param1') AS TEXT) END AS service_name,
    JSON_EXTRACT(data, '$.EventData.ImagePath') AS image_path,
    CAST(user_id AS TEXT) AS sid,
    u.username AS user,
    CAST(JSON_EXTRACT(data, '$.EventData.ServiceType') AS TEXT) AS service_type,
    CASE WHEN eventid = 7045 THEN JSON_EXTRACT(data, '$.EventData.StartType')
    WHEN eventid = 7040 THEN 'From: ' || JSON_EXTRACT(data, '$.EventData.param2') || ' to ' || JSON_EXTRACT(data, '$.EventData.param3') 
    WHEN eventid = 7036 THEN JSON_EXTRACT(data, '$.EventData.param2') END AS start_type,
    CASE WHEN eventid = '7034' THEN JSON_EXTRACT(data, '$.EventData.param2') END AS crash_count,
    'EVTX' AS data_source,
    'Service Events' AS query
FROM sophos_windows_events
LEFT JOIN users u ON user_id = u.uuid
WHERE source = 'System' 
    AND eventid IN ('7034','7035','7036','7040','7045') 
    AND time >= $$start_time$$
    AND time <= $$end_time$$
    AND service_name != ''
GROUP BY date_time, service_name, start_type
ORDER BY time DESC