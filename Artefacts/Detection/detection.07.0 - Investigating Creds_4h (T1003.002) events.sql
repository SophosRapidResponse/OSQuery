/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Get Sophos detection: Creds_4h (T1003.002), indicating the remote use of the   |
| Impacket tool SecretsDump, which is used to extract credentials from a remote  |
| host. This query retrieves key details from the event, including the source IP |
| address associated with the activity.                                          |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type: date)                                                      |
| - end_time (type: date)                                                        |
|                                                                                |
| Author: Sophos Incident Response Team                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ', datetime(detection.time, 'unixepoch')) AS date_time,
CAST(detection.detection_name AS TEXT) AS threat_name,
COALESCE(
    CASE 
        WHEN JSON_EXTRACT(detection.primary_item, '$.cleanUp') = 0 THEN 'Not Cleaned'
        WHEN JSON_EXTRACT(detection.primary_item, '$.cleanUp') = 1 THEN 'Cleaned'
    END,
    'Unknown' 
) AS status,
detection.primary_item_type AS type,
detection.primary_item_spid AS sophos_pid,
JSON_EXTRACT(detection.raw, '$.prepareTelemetryCallback.token.trigData.nodes[0].cmdline') AS process_cmdline,
CAST(GROUP_CONCAT(JSON_EXTRACT(items.value, '$.path'), ', ') AS TEXT) AS paths,  
JSON_EXTRACT(detection.raw, '$.lookupDetails.ip') AS source_ip,
detection.sid,
u.username,
detection.raw,
'detection.07.0' AS query
FROM sophos_detections_journal AS detection
JOIN json_each(JSON_EXTRACT(detection.raw, '$.items')) AS items
LEFT JOIN users AS u 
    ON detection.sid = u.uuid 
WHERE 
    detection.detection_name = 'Creds_4h (T1003.002)'
    AND detection.time BETWEEN $$start_time$$ AND $$end_time$$
GROUP BY detection.time, detection.primary_item_spid, detection.raw;