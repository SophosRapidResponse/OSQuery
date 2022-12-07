/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check for process execution, data from 'sophos_process_journal' with joins on  |
| 'user' and 'file'. Similar but simpler to 'Process.04.0'. Good for collecting  |
| small amounts of data from specific times.                                     |
|                                                                                |
| VARIABLES                                                                      |
| begin(date) = datetime of when to start hunting                                |
| end(date) = when to stop hunting                                               |
|                                                                                |
| TIP                                                                            |
| If you want to collect multiple days worth of data you can either set the      |
| begin time to 00:00:00 and the end time to 23:59:59 and collect specific days  |
| or you could use the other query 'Process.04.0' which is better for mass       |
| collection across multiple days.                                               |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
    spj.path,
    spj.cmd_line,
    spj.sophos_pid,
    spj.process_name,
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS Process_Start_Time, 
    CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch'))  END AS Process_End_Time,
    spj.sid, 
    u.username, 
    spj.sha256, 
    CASE WHEN f.btime != '' THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) ELSE 'Not on disk' END AS creation_time,
    CASE WHEN f.mtime != '' THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) ELSE 'Not on disk' END AS modified_time,
    spj.parent_sophos_pid,
    CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,
    'Process Journal/Users/File' AS Data_Source,
    'Process.07.0' AS Query 
FROM sophos_process_journal spj 
LEFT JOIN users u ON spj.sid = u.uuid
LEFT JOIN file f ON spj.path = f.path
WHERE spj.time >= $$begin$$
    AND spj.time <= $$end$$
GROUP BY spj.time, spj.sophos_pid, spj.cmd_line
ORDER BY spj.time DESC