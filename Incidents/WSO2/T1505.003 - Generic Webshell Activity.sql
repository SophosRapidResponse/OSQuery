/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query detects suspicious commandline parameters that might be associated   |
| with WebShell activity                                                         |
|                                                                                |
| VARIABLES                                                                      |
| - $$start_time$$ (date)                                                        |
| - $$end_time$$ (date)                                                          |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS Datetime,
 spj.cmd_line AS cmd_line,
 spj.sophos_pid AS sophos_PID, 
 CAST (spj.process_name AS TEXT) process_name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
 spj.sid AS sid,
 spj.parent_sophos_pid AS sophos_parent_PID, 
 CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_process,
 CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,
 'Possible WebShell Activity' As Details,
 'Process Journal/File/Users' AS Data_Source,
 'T1505.003 - WebShell Detection/Commandline' AS Query 
FROM sophos_process_journal spj 
WHERE (parent_process = 'w3wp.exe' OR parent_process = 'httpd.exe' OR parent_process LIKE 'tomcat%.exe' OR parent_process = 'nginx.exe' OR parent_process = 'beasvc.exe' OR parent_process = 'coldfusion.exe' OR parent_process = 'visualsvnserver.exe' OR parent_process = 'java.exe')
AND (process_name = 'cmd.exe' OR process_name = 'powershell.exe' OR process_name = 'powershell_ise.exe' OR process_name = 'certutil.exe')
AND spj.time > $$start_time$$ 
AND spj.time < $$end_time$$
