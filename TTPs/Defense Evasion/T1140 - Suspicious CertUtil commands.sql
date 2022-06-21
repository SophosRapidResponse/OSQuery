/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query look for evidence of suspicious certutil commands to encode/decode   |
| files/information, which can be used for data exfiltration. It also checks     |
| other arguments that can be abused by adversaries to perform C2 activities     |
|                                                                                |
| VARIABLES:                                                                     |
| - start_time: (DATE)                                                           |
| - end_time: (DATE)                                                             |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The rapid response team| Elida Leite                                   |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH suspicious_certutil_cmd(cmdline,pattern) AS (VALUES

('-decode', 'Decode Files or Information: '),
('-encode', 'Encode Files or Information: '),
('/decode', 'Decode Files or Information: '),
('/encode', 'Encode Files or Information: '),
('-urlcache', 'Suspicious CertUtil execution: '),
('-verifyctl', 'Suspicious CertUtil execution: '),
('/urlcache', 'Suspicious CertUtil execution: '),
('/verifyctl', 'Suspicious CertUtil execution: ')
)

SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS datetime,
 scc.pattern || scc.cmdline As pattern,
 spj.cmd_line AS cmd_line,
 CAST (spj.process_name AS TEXT) process_name,
 spj.path AS path, 
 spj.sophos_pid AS sophos_PID, 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
 spj.sid AS sid,
 spj.parent_sophos_pid AS sophos_parent_PID, 
 CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_process,
 CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_cmd_line,
 'Process Journal/File/Users' AS Data_Source,
 'T1140 - Suspicious CertUtil commands' AS Query 
FROM sophos_process_journal spj 
JOIN suspicious_certutil_cmd scc ON spj.cmd_line LIKE '%'|| regex_match(lower(spj.cmd_line), lower(scc.cmdline),0)||'%'
WHERE process_name IN ('certutil.exe', 'cmd.exe') AND spj.cmd_line LIKE '%certutil%'
AND spj.time >= $$start_time$$
AND spj.time <= $$end_time$$
GROUP BY datetime,  spj.sophos_pid