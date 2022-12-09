/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Looks for  MS Office applications starting Windowns commands and scripts       |
|                                                                                |
| VARIABLE:                                                                      |
| - start_time: (Type: DATE)                                                     |
| - end_time: (Type: DATE)                                                       |
|                                                                                |
| REFERENCE:                                                                     |
| https://attack.mitre.org/techniques/T1566/001/                                 |
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
    spj.path AS path, 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
    CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
    users.username,
    spj.sid,
    spj.parent_sophos_pid,
    CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_process,
    CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,
    'Process Journal/Users' AS Data_Source,
    'MS Office Spawning unusual Processes' AS Query 
FROM sophos_process_journal spj 
LEFT JOIN users ON spj.sid = users.uuid
WHERE LOWER(parent_process) IN ('winword.exe','excel.exe','powerpnt.exe', 'outlook.exe') 
    AND LOWER(process_name) IN ('cmd.exe','powershell.exe', 'wscript.exe', 'cscript.exe', 'sh.exe', 'bash.exe', 'scrcons.exe','schtasks.exe', 'regsvr32.exe', 'wmic.exe', 'mshta.exe', 'rundll32.exe', 'msdt.exe')
    AND spj.time >= $$start_time$$
    AND spj.time <= $$end_time$$