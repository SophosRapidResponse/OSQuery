/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query brings all the Windows AMSI events stored on Sophos AMSI journal     |
| The journal supports the following scripts : PowerShell, VBA, VBScript, JScript|
| and WMI                                                                        |
|                                                                                |
| VARIABLE:                                                                      |
| - start_time (date)                                                            |
| - end_time (date)                                                              |
|                                                                                |
| Version: 1.0                                                                   |
| Author: Sophos Team | Elida Leite                                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(saj.time, 'unixepoch')) AS datetime,
    spj.process_name,
    spj.cmd_line,
    saj.content As script,
    saj.content_name As script_name,
    saj.sophos_pid,
    saj.script_type,
    spa.object,
    spa.action,
    CAST ( (Select spj2.cmd_line from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_process,
    CASE
        WHEN LENGTH(saj.content) * 2 < saj.content_length THEN 'True'
        ELSE 'False'
    END AS script_is_truncated,
    saj.thumbprint As script_hash,
    saj.session_id,
    saj.session_part,
    users.username,
    saj.owner As sid,
    saj.content_length,
    'AMSI/Process/Activity Journals' AS Data_Source,
    'T1027 - Windows AMSI Events' AS Query
FROM sophos_amsi_journal AS saj
LEFT JOIN
    sophos_process_journal AS spj ON spj.sophos_pid = saj.sophos_pid
LEFT JOIN
    users ON users.uuid = saj.owner
LEFT JOIN 
    sophos_process_activity spa ON spa.sophos_pid = spj.sophos_pid
WHERE 
    saj.time >= '$$start_time$$' AND saj.time <= '$$end_time$$'
    AND NOT (saj.thumbprint = 'e60ecfdf0ff394e19092e896ec7a5342c35ec94819a6c5a176e8893ac1b0bf43' AND parent_process LIKE '%CompatTelRunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun%')
    GROUP BY saj.sophos_pid