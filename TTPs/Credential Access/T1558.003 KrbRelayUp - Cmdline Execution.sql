/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detects KrbRelayUP tool usage. This is used to perform privilege escalation    |
| in Windows domain environments where LDAP is not enforced.                     |
|                                                                                |
| VARIABLE:                                                                      |
| - start_time: (Type: DATE)                                                     |
| - end_time: (Type: DATE)                                                       |
|                                                                                |
| REFERENCE:                                                                     |
| https://github.com/Dec0ne/KrbRelayUp                                           |
| https://attack.mitre.org/techniques/T1558/003/                                 |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
    CAST (spj.process_name AS TEXT) process_name,
    spj.cmd_line,
    spj.sophos_pid,  
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
    CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
    users.username,
    spj.sid,
    spj.parent_sophos_pid, 
    CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_process,
    CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,    
    'Process Journal/File/Users' AS Data_Source,
    'T1558.003 - KrbRelay Execution' AS Query 
FROM sophos_process_journal spj 
LEFT JOIN users ON spj.sid = users.uuid
WHERE LOWER(process_name) IN ('cmd.exe', 'powershell.exe')
    AND cmd_line LIKE '%krbrelayup%'
    OR ((cmd_line like '%relay%' AND cmd_line like '%-Domain%' AND cmd_line like '%-ComputerName%')
    OR (cmd_line LIKE '%spawn%' AND cmd_line like '%-Domain%')
    OR (cmd_line LIKE '%krbscm%' AND cmd_line LIKE '%-sc%' ))
    AND spj.time >= $$start_time$$
    AND spj.time <= $$end_time$$


