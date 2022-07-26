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
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS Datetime,
 spj.path AS Path, 
 spj.cmd_line AS CMD_line,
 spj.sophos_pid AS Sophos_PID, 
 CAST (spj.process_name	 AS TEXT) Process_Name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS Process_Start_Time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS Process_End_Time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) Username,
 spj.sid AS SID,
 spj.sha256 AS Sha256,
 spj.file_size AS File_Size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) First_Created_On_Disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Accessed,
 spj.parent_sophos_pid AS Sophos_Parent_PID, 
 CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_Path,
 CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_Process,
 'Process Journal/File/Users' AS Data_Source,
 'Process.05.0' AS Query 
FROM for
 LEFT JOIN sophos_process_journal spj ON spj.time >= for.x and spj.time <= for.x+1200  