/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets AV events in the Application and Windows Defender/Operational logs for    |
| Sophos, Windows Defender, Symantec, and CarbonBlack products                   |
|                                                                                |
| Version: 1.2                                                                   |
| Author: Sophos Rapid Response Team                                             |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
provider_name AS product,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
source,
eventid,
NULL AS Category,
CASE 
   WHEN provider_name IN ('Sophos System Protection') THEN REGEX_MATCH(JSON_EXTRACT(data, '$.EventData.Data'), '^(?:[^,]*,){2}([^,]*),', 1)
   ELSE NULL 
END AS threat_name,
CASE 
   WHEN provider_name IN ('Sophos System Protection','HitmanPro.Alert') THEN REGEX_MATCH(JSON_EXTRACT(data, '$.EventData.Data'), '^([^,]*,[^,]*),', 1)
   ELSE NULL 
END AS path,
data as raw,
'AV Detections' AS query
FROM sophos_windows_events 
WHERE source = 'Application' 
AND provider_name IN ('Sophos System Protection', 'HitmanPro.Alert', 'Symantec AntiVirus', 'CbDefense')
AND eventid IN (42, 911, 5, 47, 51, 17, 33, 49)

UNION 

SELECT
'Windows Defender' AS product,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
source,
eventid,
JSON_EXTRACT(data, '$.EventData.Category Name') AS Category,
JSON_EXTRACT(data, '$.EventData.Threat Name') AS threat_name,
JSON_EXTRACT(data, '$.EventData.Path') AS path,
data as raw,
'AV Detections' AS query
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-Windows Defender/Operational' 
AND eventid IN (1006, 1007, 1008, 1009, 1010, 1011, 1116, 1117, 1118)
