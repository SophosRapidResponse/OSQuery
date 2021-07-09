/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List running processes on machines, variables for name, path, cmdline and if   |
| it is still on disk.                                                           |
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
pid AS PID,
name AS Process_Name,
path AS Path,
cmdline AS CMDLine,
parent AS Parent_PID,
CASE WHEN on_disk = 1 
THEN 'Yes' ELSE 'No' END AS On_Disk,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(start_time,'unixepoch')) AS 'Start_Time',
'Processes' AS Data_Source,
'Process.01.0' AS Query
FROM processes 
WHERE $$string_type$$ LIKE '$$value$$'