/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Collects all event logs from MOVEit. The query gathers data from event ID 0    |
| that provides information about file name, file path, size, IP address, and    |
| username.                                                                      |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
  strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
  eventid,
  data,
  source AS data_source,
  'MOVEit.01.0' AS query
FROM sophos_windows_events
WHERE
  eventid = 0
  AND source = 'MOVEit'
  AND time > 0