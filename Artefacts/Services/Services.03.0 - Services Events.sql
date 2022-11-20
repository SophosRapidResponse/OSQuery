/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look for services being installed, started/stopped, changed, or crashed via the|
| System event log and event IDs: 7034, 7035, 7036, 7040, 7045 and Security event|
| log event ID: 4697                                                             |
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

With service_changed_started_stopped AS (
SELECT
    strftime('%Y-%m-%d',datetime) AS Day,
    STRFTIME('%Y-%m-%dT%H:%M:%f', MIN(datetime)) AS date_time,
    STRFTIME('%Y-%m-%dT%H:%M:%f', MAX(datetime)) AS last_occurance,
    count (*) AS instance,
    source,
    eventid,
    CASE 
    WHEN eventid = 7040 THEN 'Start type changed' 
    ELSE 'Service started or stopped' 
    END AS details,
    '-' AS service_account,
    CASE 
    WHEN eventid = 7040 THEN JSON_EXTRACT(data, '$.EventData.param1') 
    ELSE JSON_EXTRACT(data, '$.EventData.param1') 
    END AS service_name,
    '-' AS image_path,  
    '-' AS service_type, 
    CASE 
    WHEN eventid = 7040 THEN 'From: ' || JSON_EXTRACT(data, '$.EventData.param2') || ' to ' || JSON_EXTRACT(data, '$.EventData.param3') 
    ELSE JSON_EXTRACT(data, '$.EventData.param2') END AS start_type,
    user_id AS sid,
    '-' AS user
FROM sophos_windows_events
WHERE source = 'System' 
    AND eventid IN ('7040','7036') 
    AND time >= $$start_time$$
    AND time <= $$end_time$$
GROUP BY Day, service_name, start_type
), 

service_cashed AS (
SELECT 
    strftime('%Y-%m-%d',datetime) AS Day,
    strftime('%Y-%m-%dT%H:%M:%f',datetime) AS date_time,
    '-' AS last_occurance,
    JSON_EXTRACT(data, '$.EventData.param2') AS instance,
    source, 
    eventid,
    'Service crashed unexpectedly' AS details,
    '-' AS service_account,
    JSON_EXTRACT(data, '$.EventData.param1') AS service_name,
    '-' AS image_path,
    '-' AS service_type,
    '-' start_type,
    user_id AS sid,
    '-' AS user
FROM sophos_windows_events
WHERE source = 'System' 
    AND eventid = 7034
    AND time >= $$start_time$$
    AND time <= $$end_time$$
GROUP BY date_time, service_name
), 

service_installed AS (
SELECT
    strftime('%Y-%m-%d',datetime) AS Day,
    strftime('%Y-%m-%dT%H:%M:%f',datetime) AS date_time,
    '-' AS last_occurance,
    '-' AS instance,
    source, 
    eventid,
    'A service was installed in the system' AS details,
    CAST(JSON_EXTRACT(data, '$.EventData.AccountName') AS TEXT) AS service_account,
    CAST(JSON_EXTRACT(data, '$.EventData.ServiceName') AS TEXT) AS service_name,
    JSON_EXTRACT(data, '$.EventData.ImagePath') AS image_path,
    CAST(JSON_EXTRACT(data, '$.EventData.ServiceType') AS TEXT) AS service_type,
    JSON_EXTRACT(data, '$.EventData.StartType') AS start_type,
    user_id AS sid,
    u.username AS user,
FROM sophos_windows_events
LEFT JOIN users u ON sophos_windows_events.user_id = u.uuid
WHERE source = 'System' 
    AND eventid = 7045
    AND time >= $$start_time$$
    AND time <= $$end_time$$
),

service_installed_security AS (
SELECT
    strftime('%Y-%m-%d',datetime) AS Day,
    strftime('%Y-%m-%dT%H:%M:%f',datetime) AS date_time,
    '-' AS last_occurance,
    '-' AS instance,
    source, 
    eventid,
    'A service was installed in the system' AS details,
    JSON_EXTRACT(data, '$.EventData.ServiceAccount')  AS service_account,
    JSON_EXTRACT(data, '$.EventData.ServiceName')  AS service_name,
    JSON_EXTRACT(data, '$.EventData.ServiceFileName')  AS image_path,
    CASE 
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceType')  = '0x1' THEN 'Kernel driver'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceType')  = '0x2' THEN 'File aystem driver'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceType')  = '0x8' THEN 'Recognizer driver'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceType')  = '0x10' THEN 'Runs in its own process'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceType')  = '0x20' THEN 'Share process with one or more services'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceType')  = '0x110' THEN 'Interactive Own Process'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceType')  = '0x120' THEN 'Interactive Share Process' 
    END as service_type,
    CASE 
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceStartType') = '0' THEN 'Boot'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceStartType') = '1' THEN 'System'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceStartType') = '2' THEN 'Automatic'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceStartType') = '3' THEN 'Manual startup'
    WHEN JSON_EXTRACT(data, '$.EventData.ServiceStartType') = '4' THEN 'Disabled' 
    END as start_type, 
    JSON_EXTRACT(data, '$.EventData.SubjectUserSid')  AS sid,
    JSON_EXTRACT(data, '$.EventData.SubjectUserName')  AS user
FROM sophos_windows_events 
WHERE source = 'Security'
    AND eventid = 4697
    AND time >= $$start_time$$
    AND time <= $$end_time$$
)

SELECT
*
FROM service_changed_started_stopped

UNION ALL

SELECT * FROM service_cashed

UNION ALL 

SELECT * FROM service_installed

UNION ALL 

SELECT * FROM service_installed_security
