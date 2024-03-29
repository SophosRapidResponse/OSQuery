/*************************** Sophos.com/RapidResponse ***************************\
| REQUIRES SOPHOS JOURNALS                                                       |
|                                                                                |
| DESCRIPTION                                                                    |
| Use this to find processes that were spawned by Word, Excel or PowerShell.     |
|                                                                                |
| VARIABLE                                                                       |
| begin(date) = datetime of when to start hunting                                |
| end(date) = datetime of when to stop hunting                                   |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn & Abhijit Gupta                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
 spj.path AS Path, 
 spj.cmd_line AS CMD_line,
 spj.sophos_pid	 AS Sophos_PID, 
 spj.process_name AS Process_Name,
 spj.sid AS SID,
 u.username AS Username,
 spj.parent_sophos_pid AS Sophos_Parent_PID, 
 CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_Path,
 CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_Process_Name,
 'Process Journal/Users' AS Data_Source,
 'Process.04.0' AS Query
FROM sophos_process_journal spj 
JOIN users u ON spj.sid = u.uuid
WHERE (Parent_Process_Name = 'WINWORD.EXE' OR Parent_Process_Name = 'EXCEL.EXE' OR Parent_Process_Name = 'powershell.exe' OR Parent_Process_Name = 'pwsh.exe')
AND (Process_Name != 'WINWORD.EXE' AND Process_Name != 'EXCEL.EXE')
AND spj.time >= CAST($$begin$$ AS INT) 
AND spj.time <= CAST($$end$$ AS INT)