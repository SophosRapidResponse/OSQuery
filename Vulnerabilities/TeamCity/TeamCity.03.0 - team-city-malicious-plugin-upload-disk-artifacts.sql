/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detects possible TeamCity exploitation - CVE-2024-27198                        |
| Malicious Plugin Upload Disk Artifacts                                         |                      
|                                                                                |
| Reference: https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and  |
| -cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabili  |
| ties-fixed/                                                                    |
|                                                                                |              
| Query Type: Endpoint                                                           |
| Author: The Rapid Response Team                                                |
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
WHERE
(
f.path LIKE 'C:\TeamCity\work\Catalina\localhost\ROOT\%\%' 
OR
f.path LIKE 'C:\TeamCity\webapps\ROOT\plugins\%\%' 
OR 
f.path LIKE 'C:\ProgramData\JetBrains\TeamCity\system\caches\plugins.unpacked\%\%'
)
