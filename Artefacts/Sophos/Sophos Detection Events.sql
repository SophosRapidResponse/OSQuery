/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query gets all detection events from Sophos journals.                      |
| It uses a variable called (filename) that can be used to search for a string   |
| such as (filename, file path, domain, IP).                                     |
| EXAMPLE:                                                                       |
| - malware.exe                                                                  |
| - C:\Users\%                                                                   |
| - % (wildcard gets everything)                                                 |
|                                                                                |
| VARIABLES                                                                      |
| - filename (string)                                                            |
| - start_time (date)                                                            |
| - end_time (date)                                                              |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(time,'unixepoch')) AS datetime,
    primary_item_name As item_detected,
    detection_name As threat_name,
    threat_source As threat_detection,
    detection_thumbprint As thumbprint_sha256,
    CASE
    WHEN JSON_EXTRACT(primary_item, '$.action') = 0 THEN 'Not Blocked'
    WHEN JSON_EXTRACT(primary_item, '$.action') = 1 THEN 'Blocked'
    WHEN JSON_EXTRACT(primary_item, '$.blocked') = 1 THEN 'Blocked'
    WHEN JSON_EXTRACT(primary_item, '$.blocked') = 0 THEN 'Not Blocked'
    WHEN JSON_EXTRACT(primary_item, '$.cleanUp') = 0  THEN 'Not Cleaned'
    WHEN JSON_EXTRACT(primary_item, '$.cleanUp') = 1 THEN 'Cleaned'
    ELSE '-' END as status,
    primary_item_type As type,
    sid As sid_user_logged,
    CASE WHEN sid = '' THEN '-' ELSE CAST ( (Select u.username from users u where sid = u.uuid) AS text ) END AS username,
    primary_item_spid As sophos_PID,
    CAST ( (Select cmd_line from sophos_process_journal spj where spj.sophos_pid = primary_item_spid) AS text) cmd_line, 
    CASE
    WHEN threat_source = 'HMPA' THEN regex_match(raw, '(Process Trace).*(?=Thumbprint)', 0)
    ELSE '-' END As Process_Trace,
    'Detection Journal/Users' AS Data_Source,
    'Sophos Detection' AS Query
FROM sophos_detections_journal
WHERE item_detected LIKE '%$$filename$$%'
    AND time >= $$start_time$$
    AND time <= $$end_time$$


