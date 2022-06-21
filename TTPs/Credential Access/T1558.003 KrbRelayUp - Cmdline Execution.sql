/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query detects KrbRelayUP tool being used. This is used to perform privilege|
| escalation in Windows domain environments where LDAP is not enforced.          |
|                                                                                |
| Reference:                                                                     |
| https://github.com/Dec0ne/KrbRelayUp                                           |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS datetime,
 spj.cmd_line AS cmd_line,
 spj.sophos_pid AS sophos_PID, 
 CAST (spj.process_name AS TEXT) process_name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
 spj.sid AS sid,
 spj.parent_sophos_pid AS sophos_parent_PID, 
 CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,
 'Process Journal/File/Users' AS Data_Source,
 'T1558.003 - KrbRelay Execution' AS Query 
FROM sophos_process_journal spj 
WHERE lower(process_name) IN ('cmd.exe', 'powershell.exe')
AND cmd_line LIKE '%krbrelayup%'
OR ((cmd_line like '%relay%' AND cmd_line like '%-Domain%' AND cmd_line like '%-ComputerName%')
    OR (cmd_line LIKE '%spawn%' AND cmd_line like '%-Domain%')
    OR (cmd_line LIKE '%krbscm%' AND cmd_line LIKE '%-sc%' ))
AND spj.time > STRFTIME('%s','NOW','-15 DAYS')


