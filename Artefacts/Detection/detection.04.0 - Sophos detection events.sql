/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets all detection events from Sophos detection journal within a time range.   |
| The variable 'filename' can be used to search for a filename, file path, IP,   |
| domain, and so on.                                                             |
|                                                                                |
| EXAMPLE:                                                                       |
| - malware.exe                                                                  |
| - C:\Users\%                                                                   |
| - % (wildcard gets everything)                                                 |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type: date)                                                      |
| - end_time (type: date)                                                        |
| - filename (type: string)                                                      |
|                                                                                |
| Version: 1.2                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(detection.time,'unixepoch')) AS date_time,
CAST(detection.primary_item_name AS TEXT) AS item_detected,
CAST(detection.detection_name AS TEXT) As threat_name,
detection.threat_source As threat_detection,
CASE 
    WHEN detection.threat_source = 'Device Control' THEN NULL 
    ELSE detection.detection_thumbprint
END AS thumbprint,
CASE
    WHEN JSON_EXTRACT(detection.primary_item, '$.action') = 0 THEN 'Not Blocked'
    WHEN JSON_EXTRACT(detection.primary_item, '$.action') = 1 THEN 'Blocked'
    WHEN JSON_EXTRACT(detection.primary_item, '$.action') = 'alertedOnly' THEN 'alertedOnly'
    WHEN JSON_EXTRACT(detection.primary_item, '$.blocked') = 1 THEN 'Blocked'
    WHEN JSON_EXTRACT(detection.primary_item, '$.blocked') = 0 THEN 'Not Blocked'
    WHEN JSON_EXTRACT(detection.primary_item, '$.cleanUp') = 0  THEN 'Not Cleaned'
    WHEN JSON_EXTRACT(detection.primary_item, '$.cleanUp') = 1 THEN 'Cleaned'
    ELSE NULL 
END AS status,
detection.primary_item_type As type,
detection.sid,
u.uid,
u.username,
detection.primary_item_spid As sophos_pid,
CASE 
    WHEN detection.threat_source = 'HMPA' THEN regex_match(raw, '(Process Trace).*(?=Thumbprint)', 0)
    ELSE NULL 
END As Process_Trace,
detection.raw,
'Detection Journal/Users' AS data_source,
'detection.04.0' AS Query
FROM sophos_detections_journal detection
LEFT JOIN users AS u 
    ON (detection.sid = u.uuid OR detection.sid = u.uid)
WHERE detection.raw LIKE '$$filename$$'
    AND detection.time >= $$start_time$$
    AND detection.time <= $$end_time$$
GROUP BY detection.time