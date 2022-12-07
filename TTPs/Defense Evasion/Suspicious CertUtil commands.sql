/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detects suspicious certutil commands associated with encoding/decoding files,  |
| and file download activity from the internet.                                  |
|                                                                                |
| VARIABLES:                                                                     |
| - start_time: (DATE)                                                           |
| - end_time: (DATE)                                                             |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/techniques/T1140/                                     |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The rapid response team| Elida Leite                                   |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH suspicious_certutil_cmd(cmdline,pattern) AS (VALUES

('-decode', 'Decode files/information: '),
('-encode', 'Encode files/information: '),
('/decode', 'Decode files/information: '),
('/encode', 'Encode files/information: '),
('-urlcache', 'Download files: '),
('-verifyctl', 'Download files: '),
('/urlcache', 'Download files: '),
('/verifyctl', 'Download files: ')
)

SELECT 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.time,'unixepoch')) AS date_time,
    scc.pattern || scc.cmdline As pattern,
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
    'Suspicious CertUtil commands' AS Query 
FROM sophos_process_journal spj 
LEFT JOIN users ON spj.sid = users.uuid
JOIN suspicious_certutil_cmd scc ON spj.cmd_line LIKE '%'|| regex_match(lower(spj.cmd_line), lower(scc.cmdline),0)||'%'
WHERE process_name IN ('certutil.exe', 'cmd.exe') AND spj.cmd_line LIKE '%certutil%'
    AND spj.time >= $$start_time$$
    AND spj.time <= $$end_time$$
GROUP BY date_time,  spj.sophos_pid