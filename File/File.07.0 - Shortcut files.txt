/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look at the two 'Recent' locations for a user to see that shortcut (.lnk)      |
| files exist, this gives you an idea of what the user was looking at.           |
|                                                                                |
| VARIABLE                                                                       |
| - username (string)                                                            |
| - IOC (string): If want to search for a specific file .eg (.exe) or (malware)  ||                                                                                |
| IMPORTANT                                                                      |
| The table "shortcut_files" was deprecated on the osquery version 5.2.3 due to  |
| possible security issues. Therefore, we are reverting back the old query using |
| the file table.                                                                |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn | Elida Leite                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
path AS Path,
filename AS Filename,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(btime,'unixepoch')) AS First_Created_On_Disk, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(ctime,'unixepoch')) AS Last_Changed, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS Last_Modified, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(atime,'unixepoch')) AS Last_Accessed,
'File' AS Data_Source,
'File.07.0 - Shortcut_file' AS Query
FROM file 
WHERE path LIKE 'C:\Users\$$username$$\AppData\Roaming\Microsoft\%\Recent\%'
AND (filename != '.' AND filename LIKE '%$$IOC$$%')