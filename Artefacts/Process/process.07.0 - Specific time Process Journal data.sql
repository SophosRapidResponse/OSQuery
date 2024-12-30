/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check for process execution, data from 'sophos_process_journal'. Similar but   |
| simpler to 'Process.04.0'. This is good for collecting small amounts of data   |
| from specific times.                                                           |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (TYPE: DATE) = datetime of when to start hunting                  |
| - end_time (TYPE: DATE) = when to stop hunting                                 |
|                                                                                |
| TIP                                                                            |
| If you want to collect multiple days worth of data you can either set the      |
| begin time to 00:00:00 and the end time to 23:59:59 and collect specific days  |
| or you could use the other query 'Process.04.0' which is better for mass       |
| collection across multiple days.                                               |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
spj.path,
spj.process_name,
spj.cmd_line,
spj.sophos_pid,
CAST(strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS TEXT) AS Process_Start_Time, 
CASE 
    WHEN spj.end_time = 0 THEN NULL 
    ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) 
END AS Process_End_Time,
spj.sid,
u.username,
spj.sha256,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS creation_time,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS modified_time,
spj.parent_sophos_pid,
CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,
'Process Journal/Users/File' AS Data_Source,
'Process.07.0' AS Query
FROM sophos_process_journal spj
LEFT JOIN users u ON spj.sid = u.uuid
LEFT JOIN file f ON spj.path = f.path
WHERE spj.time >= CAST($$start_time$$ AS INT)
    AND spj.time <= CAST($$end_time$$ AS INT)