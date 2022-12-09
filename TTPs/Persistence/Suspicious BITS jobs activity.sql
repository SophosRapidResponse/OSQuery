/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look for suspicious commands from the BITSAdmin tool, and Powershell cmdlet    |
| used to start BITS jobs                                                        |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type: DATE)                                                      |
| - end_time (type: DATE)                                                        |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/techniques/T1197/                                     |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
    CAST (spj.process_name AS TEXT) process_name,
    spj.cmd_line,
    spj.sophos_pid,
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
    CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
    users.username,
    spj.sid,
    spj.parent_sophos_pid, 
    CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_process,
    CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,
    'Process Journal/Users' AS data_source,
    'BITS Job activity' AS query 
FROM sophos_process_journal spj 
LEFT JOIN users ON spj.sid = users.uuid
WHERE (process_name = 'bitsadmin.exe' 
    AND (cmd_line LIKE '%Transfer%' OR cmd_line LIKE '%Create%' OR cmd_line LIKE '%AddFile%' OR cmd_line LIKE '%SetNotifyCmdLine%' OR cmd_line LIKE '%SetMinRetryDelay%' OR cmd_line LIKE '%Resume%'))
    OR ( process_name IN ('powershell.exe','powershell_ise.exe') AND cmd_line like '%Start-BitsTransfer%')
    AND spj.time > $$start_time$$ 
    AND spj.time < $$end_time$$
GROUP BY date_time, sophos_pid