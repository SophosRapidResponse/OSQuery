/*********************************************** Sophos.com/RapidResponse *******************************************\
| DESCRIPTION                                                                                                         |
| Detects suspicious arguments passed to the msdt.exe and PowerShell processes that could indicate exploitation of    |
| CVE-2022-30190 AKA "Follina"                                                                                        |
|                                                                                                                     |
| VARIABLES:                                                                                                          |
| - start_time: (DATE)                                                                                                |
| - end_time: (DATE)                                                                                                  |
|                                                                                                                     |
| REFERENCE:                                                                                                          |
| https://news.sophos.com/en-us/2022/05/30/malicious-word-doc-taps-previously-unknown-microsoft-office-vulnerability/ |
|                                                                                                                     |
| Version: 1.0                                                                                                        |
| Author: The Rapid Response Team| Elida Leite                                                                        |
| github.com/SophosRapidResponse                                                                                      |
\*********************************************************************************************************************/

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
    CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_process,
    CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_cmd_line,
    'Process Journal/Users' AS Data_Source,
    'Follina - Suspicious cmdline execution' AS Query 
FROM sophos_process_journal spj 
LEFT JOIN users ON spj.sid = users.uuid
WHERE (process_name = 'msdt.exe' AND (spj.cmd_line LIKE '%ms-msdt:/id%PCWDiagnostic%' OR spj.cmd_line LIKE '%ms-msdt:-id%PCWDiagnostic%'))
    OR (process_name IN ('powershell.exe', 'powershell_ise.exe') AND (spj.cmd_line LIKE '%wget%.html%' OR spj.cmd_line LIKE '%Invoke-WebRequest%.html%'))
    AND spj.time >= $$start_time$$ 
    AND spj.time <= $$end_time$$