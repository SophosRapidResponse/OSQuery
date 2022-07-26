/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Finds all the ConsoleHost_history.txt files and then Greps the content,        |
| matching on ' ' (a space) which should return most rows but may miss some.     |
|                                                                                |
| NOTE                                                                           |
| The Last_Modified value is for the txt file itself, it doesn't tell you when   |
| the commands were executed, just the last time the file changed. So for        |
| example if your attack was a week ago and the last modified date was months    |
| ago, then it is unlikely that any of the commands are relevant.                |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
( SELECT path FROM file WHERE path LIKE 'C:\Users\%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' ) AS File_Path,
( SELECT strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) FROM file WHERE path LIKE 'C:\Users\%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' ) AS Last_Modified,
 line,
 'Grep/ConsoleHost_history' AS Data_Source,
 'PowerShell.02.0' AS Query
FROM grep
WHERE pattern = ' '
AND path = File_Path