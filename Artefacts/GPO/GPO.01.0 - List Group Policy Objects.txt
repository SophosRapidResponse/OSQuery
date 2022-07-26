/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List GPO scripts files, search by filename and dates.                          |
|                                                                                |
| VARIABLES                                                                      |
| filename(string) - filename of script                                          |
|                                                                                |
| TIP                                                                            |
| If you want to bring back everything use % in 'filename' and btime for         |
| 'time_type' then set 'begin' as a few years ago.                               |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
f.path AS Path,
f.filename AS Filename,
f.size AS Size,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) AS 'Last_Status_Change(ctime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) AS 'Last_Accessed(atime)',
h.sha256 AS SHA256,
'GPO' AS Data_Source,
'GPO.01.0' AS Query
FROM file f 
JOIN hash h ON f.path = h.path
WHERE f.path LIKE 'C:\Windows\SYSVOL\sysvol\%\Policies\%\%\Scripts\%%' AND filename LIKE '$$filename$$' AND filename != '.' AND filename NOT LIKE '%.ini'