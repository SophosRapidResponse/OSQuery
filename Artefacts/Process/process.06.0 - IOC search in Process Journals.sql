/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check for process execution using data from 'sophos_process_journal'. This     |
| query allows you to filter results based on specified variables, such as a     |
| process name, command line, and hash.                                          |
|                                                                                |
| VARIABLES                                                                      |
| begin(date) = datetime of when to start hunting                                |
| days(string) = how many days to search through                                 |
| ioc1(string) = IOC to hunt (process, cmd, path, sha256 of the process)         |
| ioc2(string) = IOC to hunt (process, cmd, path, sha256 of the process)         |
| ioc3(string) = IOC to hunt (process, cmd, path, sha256 of the process)         |
|                                                                                |
| TIP                                                                            |
| If you only want to use one variable put something that wont be found in the   |
| others e.g. zzzzzzzz                                                           |
|                                                                                |
| Version: 1.3                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH for(x) AS (
   VALUES ( (CAST ($$begin$$ AS INT) ) )
   UNION ALL
   SELECT x+1200 FROM for WHERE x < (CAST ($$begin$$ AS INT) + CAST( ($$days$$ * 86400) AS INT))
)

SELECT DISTINCT
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
   spj.file_size, 
   CASE WHEN f.btime != '' THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) ELSE 'Not on disk' END AS creation_time,
   CASE WHEN f.mtime != '' THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) ELSE 'Not on disk' END AS modified_time,
   CASE WHEN f.ctime != '' THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) ELSE 'Not on disk' END AS last_changed,
   CASE WHEN f.atime != '' THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) ELSE 'Not on disk' END AS last_accessed,
   spj.parent_sophos_pid, 
   CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_Path,
   'Process Journal/File/Users' AS Data_Source,
   'Process.06.0' AS Query 
FROM for
   LEFT JOIN sophos_process_journal spj ON spj.time >= for.x and spj.time <= for.x+1200
   LEFT JOIN users u ON spj.sid = u.uuid 
   LEFT JOIN file f ON spj.path = f.path
WHERE (spj.sha256 LIKE '$$ioc1$$' OR spj.sha256 LIKE '$$ioc2$$' OR spj.sha256 LIKE '$$ioc3$$') 
   OR (spj.process_name LIKE '$$ioc1$$' OR spj.process_name LIKE '$$ioc2$$' OR spj.process_name LIKE '$$ioc3$$') 
   OR (spj.path LIKE '$$ioc1$$' OR spj.path LIKE '$$ioc2$$' OR spj.path LIKE '$$ioc3$$') 
   OR (spj.cmd_line LIKE '$$ioc1$$' OR spj.cmd_line LIKE '$$ioc2$$' OR spj.cmd_line LIKE '$$ioc3$$') 
