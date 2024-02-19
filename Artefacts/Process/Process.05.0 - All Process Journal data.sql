/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check for process execution, data from 'sophos_process_journal' with joins on  |
| 'user' and 'file'. Choose the start date and then how many days to collect.    |
|                                                                                |
| VARIABLES                                                                      |
| begin(date) = datetime of when to start hunting                                |
| days(string) = how many days to search through                                 |
|                                                                                |
| TIP                                                                            |
| You can do multiple days, but you are asking for a lot of data so if it fails  |
| do one day at a time.                                                          |
|                                                                                |
| Version: 1.1                                                                   |
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
CASE 
   WHEN spj.end_time = 0 THEN '' 
   ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) 
END AS Process_End_Time, 
u.username,
spj.sid,
spj.sha256,
spj.file_size,  
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS creation_time,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) AS last_changed,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS modified_time,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) AS last_accessed,
spj.parent_sophos_pid, 
CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,
'Process Journal/File/Users' AS Data_Source,
'Process.05.0' AS Query 
FROM for
 LEFT JOIN sophos_process_journal spj 
   ON spj.time >= for.x and spj.time <= for.x+1200
 LEFT JOIN users u ON spj.sid = u.uuid
 LEFT JOIN file f ON spj.path = f.path