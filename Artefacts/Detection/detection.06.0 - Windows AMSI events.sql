/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all Windows AMSI events from Sophos AMSI journal.                         |
| The journal supports the following scripts : PowerShell, VBA, VBScript, JScript|
| and WMI                                                                        |
|                                                                                |
| Users can search for a specific keyword in the script body by assigning a value|
| to the variable "ioc" or use % as a wildcard to get everything                 |
|                                                                                |
| VARIABLE:                                                                      |
| - start_time (type: DATE)                                                      |
| - end_time (type: DATE)                                                        |
| - ioc (type: STRING)                                                           |
|                                                                                |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(saj.time, 'unixepoch')) AS date_time,
    saj.script_type,
    spj.process_name,
    spj.cmd_line,
    saj.sophos_pid,
    saj.content AS script,
    saj.content_name AS script_name,    
    CASE
        WHEN LENGTH(saj.content) * 2 < saj.content_length THEN 'True'
        ELSE 'False'
    END AS script_truncated,
    saj.thumbprint AS script_hash,
    saj.session_id,
    saj.session_part,
    users.username,
    saj.owner AS sid,
    saj.content_length,
    spj.parent_sophos_pid,
    CAST ( (SELECT spj2.cmd_line FROM sophos_process_journal spj2 WHERE spj2.sophos_pid = spj.parent_sophos_pid) AS TEXT) parent_cmdline,
    'T1027 - Windows AMSI Events' AS Query
FROM sophos_amsi_journal saj
LEFT JOIN sophos_process_journal spj USING(sophos_pid)
LEFT JOIN users ON users.uuid = saj.owner
WHERE saj.content LIKE '$$ioc$$' 
    AND saj.time >= '$$start_time$$' 
    AND saj.time <= '$$end_time$$'