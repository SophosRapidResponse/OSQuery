/*********************************************** Sophos.com/RapidResponse *******************************************\
| DESCRIPTION                                                                                                         |
| Detects suspicious arguments passed to msdt.exe and PowerShell processes that could indicate exploitation of        |
| CVE-2022-30190, \"Follina\".                                                                                        |
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
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(spj.time, 'unixepoch')) AS date_time,
    CAST(spj.process_name AS TEXT) AS process_name,
    spj.cmd_line,
    spj.sophos_pid,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(spj.process_start_time, 'unixepoch')) AS process_start_time, 
    IFNULL(strftime('%Y-%m-%dT%H:%M:%SZ', datetime(spj.end_time, 'unixepoch')), '') AS process_end_time, 
    users.username,
    spj.sid,
    spj.parent_sophos_pid,
    CAST(spj_parent.process_name AS TEXT) AS parent_process,
    CAST(spj_parent.cmd_line AS TEXT) AS parent_cmd_line,
    'Process Journal/Users' AS Data_Source,
    'Follina exploit' AS Query 
FROM sophos_process_journal spj
LEFT JOIN users ON spj.sid = users.uuid
LEFT JOIN sophos_process_journal spj_parent ON spj.parent_sophos_pid = spj_parent.sophos_pid
WHERE 
    (
        spj.process_name = 'msdt.exe' AND (
            spj.cmd_line LIKE '%ms-msdt:/id%PCWDiagnostic%' OR 
            spj.cmd_line LIKE '%ms-msdt:-id%PCWDiagnostic%'
        )
    )
    OR 
    (
        spj.process_name IN ('powershell.exe', 'powershell_ise.exe') AND (
            spj.cmd_line LIKE '%wget%.html%' OR 
            spj.cmd_line LIKE '%Invoke-WebRequest%.html%'
        )
    )
    AND spj.time >= $$start_time$$ 
    AND spj.time <= $$end_time$$
