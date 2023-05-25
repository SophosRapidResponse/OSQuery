/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets detections events for Microsoft Windows Defender stored in the Windows    |
| event log (Microsoft-Windows-Windows Defender/Operational)                     |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
source,
eventid,
JSON_EXTRACT(data, '$.EventData.Category Name') AS Category,
JSON_EXTRACT(data, '$.EventData.Threat Name') AS threat_name,
JSON_EXTRACT(data, '$.EventData.Path') AS path,
data as raw,
'Windows Defender Logs' AS query
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-Windows Defender/Operational' 
AND eventid in ('1006', '1007', '1008', '1009', '1010', '1011' , '1116' , '1117' , '1118')


