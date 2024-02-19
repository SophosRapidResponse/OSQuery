/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look for evidence of Rclone execution on Windows devices.                      |
| The query might bring FP results                                               |
|                                                                                |
| VARIABLES                                                                      |
| - start_time(date)                                                             |
| - end_time (date)                                                              |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/techniques/T1567/002/                                 |
|                                                                                |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
    spj.path, 
    spj.process_name,
    spj.cmd_line,
    spj.sophos_pid, 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS Process_Start_Time, 
    CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS Process_End_Time, 
    u.username,
    spj.sid,
    spj.sha256,
    CASE WHEN f.btime != '' THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) ELSE 'Not on disk' END AS creation_time,
    CASE WHEN f.mtime != '' THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) ELSE 'Not on disk' END AS modified_time,
    spj.parent_sophos_pid, 
    CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_process,
    'Process Journal/File/Users' AS Data_Source,
    'Rclone commandline' AS Query 
FROM sophos_process_journal spj 
LEFT JOIN users u ON spj.sid = u.uuid 
LEFT JOIN file f ON spj.path = f.path
WHERE parent_process IN ('cmd.exe', 'powershell.exe','wt.exe')
    AND LOWER(process_name) NOT IN ('robocopy.exe', 'ipconfig.exe', 'xcopy.exe', 'net.exe', 'java.exe')
    AND (cmd_line like '%-pass %' 
    OR cmd_line like '%user %' 
    OR cmd_line like '%copy %' 
    OR cmd_line like '%sync %' 
    OR cmd_line like '%config %' 
    OR cmd_line like '%lsd %' 
    OR cmd_line like '%remote %' 
    OR cmd_line like '%ls %' 
    OR cmd_line like '%rcd %' 
    OR cmd_line like '%move %'
    OR cmd_line like '%--transfer%'
    OR cmd_line like '%--no-check-certificate %')
    AND spj.time > $$start_time$$ 
    AND spj.time < $$end_time$$