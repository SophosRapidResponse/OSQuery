/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Lists BITS job start events in the Windows-Bits-Client/Operational logs, event  |
| ID 59. The query also searches for suspicious commands using the BITSAdmin tool |
| and PowerShell cmdlets used to start BITS jobs in Process Journals within a     |
| specified time range.                                                           |
|                                                                                 |
| VARIABLES                                                                       |
| - start_time (type: DATE)                                                       |
| - end_time (type: DATE)                                                         |
|                                                                                 |
| REFERENCE                                                                       |
| https://attack.mitre.org/techniques/T1197/                                      |
|                                                                                 |
| Query Type: Endpoint                                                            |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


WITH bits_evtx AS (
SELECT 
'Windows-Bits-Client/Operational' AS data_source,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,     
eventid,
JSON_EXTRACT(data, '$.EventData.name') As job_title,
JSON_EXTRACT(data, '$.EventData.url') As URL,
JSON_EXTRACT(data, '$.EventData.bytesTotal') As bytes_total,
JSON_EXTRACT(data, '$.EventData.fileLength') As file_length,
JSON_EXTRACT(data, '$.EventData.fileTime') As file_time,
NULL AS process_name,
NULL AS cmd_line,
NULL AS sophos_pid,
NULL AS process_start_time,
NULL AS process_end_time,
NULL AS username,
NULL AS sid,
NULL AS parent_sophos_pid,
NULL AS parent_process,
NULL AS parent_cmdline,
'EVTX.12.0' AS Query
FROM sophos_windows_events 
WHERE source ='Microsoft-Windows-Bits-Client/Operational' 
    AND eventid = '59'
    AND time >= $$start_time$$
    AND time <= $$end_time$$
GROUP BY job_title
ORDER BY date_time DESC
),

bits_journals AS (
SELECT 
'Process Journal' AS data_source,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
NULL AS eventid,
NULL AS job_title,
NULL AS URL,
NULL AS bytes_total,
NULL AS file_length,
NULL AS file_time,
CAST (spj.process_name AS TEXT) process_name,
spj.cmd_line,
spj.sophos_pid,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
users.username,
spj.sid,
spj.parent_sophos_pid, 
spp.process_name AS parent_process_name,
spp.cmd_line AS parent_cmdline,
'EVTX.12.0' AS Query
FROM sophos_process_journal spj 
JOIN sophos_process_journal spp ON spp.sophos_pid = spj.parent_sophos_pid
LEFT JOIN users ON spj.sid = users.uuid
WHERE (spj.process_name = 'bitsadmin.exe' 
    AND (spj.cmd_line LIKE '%Transfer%' 
    OR spj.cmd_line LIKE '%Create%' 
    OR spj.cmd_line LIKE '%AddFile%' 
    OR spj.cmd_line LIKE '%SetNotifyCmdLine%' 
    OR spj.cmd_line LIKE '%SetMinRetryDelay%' 
    OR spj.cmd_line LIKE '%Resume%'))
    OR ( spj.process_name IN ('powershell.exe','powershell_ise.exe') AND spj.cmd_line LIKE '%Start-BitsTransfer%')
    AND spj.time > $$start_time$$ 
    AND spj.time < $$end_time$$
GROUP BY spj.time, spj.sophos_pid
)

SELECT * FROM bits_evtx
UNION 
SELECT * FROM bits_journals