/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Find suspicious command-line entries that might indicate use of the impacket   |
| tool. Impacket is a collection of Python scripts for working with Microsoft    |
| network protocols. Adversaries may leverage impacket for lateral movement and  |
| remote code execution.                                                         |
|                                                                                |
| VARIABLES                                                                      |
| - star_time (type: DATE)                                                       |
| - end_time (type: DATE)                                                        |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/software/S0357/                                       |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
spj.cmd_line,
spj.process_name,
spj.sophos_pid, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
CASE 
    WHEN spj.end_time = 0 THEN '' 
    ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) 
END AS process_end_time, 
u.username,
spj.sid,
spj.parent_sophos_pid,
spp.process_name AS parent_process,
spp.cmd_line AS parent_cmd_line,
'Impacket Commands' AS query
FROM sophos_process_journal spj
LEFT JOIN users u ON spj.sid = u.uuid
JOIN sophos_process_journal spp ON spp.sophos_pid = spj.parent_sophos_pid
WHERE LOWER(spp.process_name) IN ('wmiprvse.exe', 'mmc.exe', 'explorer.exe', 'services.exe','svchost.exe','taskeng.exe') 
AND ((spj.cmd_line LIKE '%cmd.exe /Q /c %') OR (spj.cmd_line LIKE 'cmd.exe /C % C:\Windows\Temp\%'))
AND spj.time >= $$start_time$$
AND spj.time <= $$end_time$$
GROUP BY spj.time, spj.sophos_pid, spj.cmd_line
ORDER BY spj.time DESC