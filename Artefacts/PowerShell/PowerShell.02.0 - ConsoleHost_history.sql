/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets all data from the ConsoleHost_history.txt files                           |
|                                                                                |
| NOTE                                                                           |
| The Last_Modified value is for the txt file itself, it doesn't tell you when   |
| the commands were executed, just the last time the file changed. Look at the   |
| other powershell events to get more details about the commands executed        |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn | Elida Leite                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT 
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS Modified_time,
   f.path,
   (SELECT CAST(GROUP_CONCAT(line,CHAR(10)) AS TEXT) FROM grep WHERE pattern IN (CHAR(0),CHAR(10),CHAR(32)) AND path = f.path) AS Console_History,
 'Grep/File' AS Data_Source,
 'PowerShell_ConsoleHistory' AS Query
FROM file f
WHERE f.path LIKE 'C:\Users\%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
   AND Console_History != ''