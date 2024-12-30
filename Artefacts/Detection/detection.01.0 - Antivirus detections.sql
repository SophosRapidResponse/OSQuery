/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets events from the Windows Application event logs from antivirus products    |
| such as Sophos, Symantec, and Carbon Black.                                    |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.2                                                                   |
| Author: Sophos Rapid Response Team                                             |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
provider_name AS product,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
source,
eventid,
CASE 
   WHEN provider_name IN ('Sophos System Protection') THEN REGEX_MATCH(JSON_EXTRACT(data, '$.EventData.Data'), '^(?:[^,]*,){2}([^,]*),', 1)
   ELSE NULL 
END AS threat_name,
CASE 
   WHEN provider_name IN ('Sophos System Protection','HitmanPro.Alert') THEN REGEX_MATCH(JSON_EXTRACT(data, '$.EventData.Data'), '^([^,]*,[^,]*),', 1)
   ELSE NULL 
END AS path,
data AS raw_data,
'EVTX' AS data_source,
'detection.01.0' AS query
FROM sophos_windows_events 
WHERE source = 'Application' 
AND provider_name IN ('Sophos System Protection', 'HitmanPro.Alert', 'Symantec AntiVirus', 'CbDefense')
AND eventid IN (42, 911, 5, 47, 51, 17, 33, 49)
AND time > 0
ORDER BY time DESC