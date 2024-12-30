/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists running processes on devices with variables for name, path, command line,|
| and if it's still on disk. Also adds parent details.                           |
|                                                                                |
| VARIABLE                                                                       |
| string_type(string) - pid, parent, name, path, cmdline, on_disk                |
| value(string) - string to search for in string_type                            |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
p.pid AS PID,
p.name AS Process_Name,
p.path AS Path,
p.cmdline AS CMDLine,
p.parent AS Parent_PID,
CAST ( (Select name from processes p2 where p.parent = p2.pid) AS text) Parent_Process_Name,
CAST ( (Select path from processes p2 where p.parent = p2.pid) AS text) Parent_Path,
CAST ( (Select cmdline from processes p2 where p.parent = p2.pid) AS text) Parent_CMDLine,
CASE WHEN p.on_disk = 1 
THEN 'Yes' ELSE 'No' END AS On_Disk,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(p.start_time,'unixepoch')) AS 'Start_Time',
'Processes' AS Data_Source,
'Process.01.1' AS Query
FROM processes p
WHERE $$string_type$$ LIKE '$$value$$'