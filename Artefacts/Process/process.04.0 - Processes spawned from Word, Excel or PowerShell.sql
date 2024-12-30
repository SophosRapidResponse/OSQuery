/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Use this to find processes that were spawned by Word, Excel or PowerShell.     |
|                                                                                |
| VARIABLE                                                                       |
| start_time(date) = datetime of when to start hunting                           |
| end_time(date) = datetime of when to stop hunting                              |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn & Abhijit Gupta                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    spj.path AS Path, 
    spj.cmd_line AS CMD_Line,
    spj.sophos_pid AS Sophos_PID, 
    spj.process_name AS Process_Name,
    spj.sid AS SID,
    u.username AS Username,
    spj.parent_sophos_pid AS Sophos_Parent_PID, 
    spj2.process_name AS Parent_Process_Name,
    'Process Journal/Users' AS Data_Source,
    'Process.04.0' AS Query
FROM 
    sophos_process_journal spj
JOIN 
    sophos_process_journal spj2 ON spj2.sophos_pid = spj.parent_sophos_pid
JOIN 
    users u ON spj.sid = u.uuid
WHERE 
    LOWER(spj2.process_name) IN ('winword.exe', 'excel.exe', 'powershell.exe') 
    AND LOWER(spj.process_name) NOT IN ('winword.exe', 'excel.exe')
    AND spj.time BETWEEN CAST($$start_time$$ AS INT) AND CAST($$end_time$$ AS INT);