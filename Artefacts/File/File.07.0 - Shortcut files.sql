/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This query examines a specific user's \"Recent\" folders to identify shortcut  |
| (.lnk) files, providing insight into the files the user accessed recently.     |
|                                                                                |
| VARIABLE                                                                       |
| - username (string)                                                            |
| - filename (string): filename to search for                                    |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn | Elida Leite                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
path,
filename,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(btime,'unixepoch')) AS First_Created_On_Disk, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(ctime,'unixepoch')) AS Last_Changed, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS Last_Modified, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(atime,'unixepoch')) AS Last_Accessed,
'File' AS Data_Source,
'File.07.0' AS Query
FROM file 
WHERE path LIKE 'C:\Users\$$username$$\AppData\Roaming\Microsoft\%\Recent\%'
AND filename != '.' 
AND filename LIKE '%$$filename$$%'
ORDER BY btime DESC;