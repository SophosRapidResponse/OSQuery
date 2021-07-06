/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check for REvil/Kaseya files still on disk.                                    |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
f.path AS Path,
f.directory AS Directory,
f.filename AS Filename,
f.size AS Size,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) AS 'Last_Status_Change(ctime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) AS 'Last_Accessed(atime)',
h.sha256 AS SHA256,
h.sha1 AS SHA1,
h.md5 AS MD5,
f.attributes AS Attributes,
f.file_version AS File_Version
FROM file f 
JOIN hash h ON f.path = h.path
WHERE f.path LIKE 'C:\Windows\mpsvc.dll' OR f.path LIKE 'C:\Windows\cert.exe' OR f.path LIKE 'C:\Windows\agent.crt' OR f.path LIKE 'C:\kworking\agent.exe'