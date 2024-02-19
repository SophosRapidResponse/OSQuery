/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets detections events in the Windows Defender/Operational logs. The query     |
| looks for the EIDs 1006, 1007, 1008, 1009, 1010, 1011, 1116, 1117, 1118.       |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
source,
eventid,
JSON_EXTRACT(data, '$.EventData.Category Name') AS category,
JSON_EXTRACT(data, '$.EventData.Threat Name') AS threat_name,
JSON_EXTRACT(data, '$.EventData.Path') AS path,
data as raw,
'EVTX' source_data,
'detection.02.0' AS query
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-Windows Defender/Operational' 
AND eventid in ('1006', '1007', '1008', '1009', '1010', '1011' , '1116' , '1117' , '1118')


