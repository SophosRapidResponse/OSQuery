/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detects suspicious commands that might be associated with webshell activity    |
|                                                                                |
| VARIABLES                                                                      |
| - start_time: (Type: DATE)                                                     |
| - end_time: (Type: DATE)                                                       |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/techniques/T1505/003/                                 |
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
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
CASE 
    WHEN spj.end_time = 0 THEN '' 
    ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) 
END AS process_end_time, 
users.username,
spj.sid,
spj.parent_sophos_pid,
spp.process_name AS parent_process,
spp.cmd_line AS parent_cmd_line,
'Process Journal' AS Data_Source,
'Webshell Activity' AS Query 
FROM sophos_process_journal spj
LEFT JOIN users ON spj.sid = users.uuid
JOIN sophos_process_journal spp ON spp.sophos_pid = spj.parent_sophos_pid
WHERE (spp.process_name IN ('w3wp.exe','httpd.exe','nginx.exe','beasvc.exe','coldfusion.exe','visualsvnserver.exe','java.exe') OR spp.process_name LIKE 'tomcat%.exe')
    AND spj.process_name IN ('cmd.exe','powershell.exe','powershell_ise.exe','certutil.exe')
    AND spj.time >= $$start_time$$ 
    AND spj.time <= $$end_time$$
