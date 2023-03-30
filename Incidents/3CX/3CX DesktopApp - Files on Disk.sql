/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identify files on disk associated with 3CX Desktop App on Windows. It also     |
| highlights if the DLLs listed are known malicious                              |
|                                                                                |
| REFERENCE                                                                      |
| https://news.sophos.com/en-us/2023/03/29/3cx-dll-sideloading-attack/           |
| https://www.3cx.com/blog/news/desktopapp-security-alert/                       |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT 
f.filename, 
f.path, 
f.size, 
h.sha256, 
CASE
    WHEN h.sha256 IN ('c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02','256c485674ee63ec8d4e8fde9800788175a8b02d3f9416d0e763360fff7f8eb4e02','7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896') THEN 'True'
    WHEN h.sha256 IN ('11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03') THEN 'True'
    ELSE NULL
END AS malicious,
datetime(f.btime,'unixepoch') AS creation_time,
datetime(f.atime,'unixepoch') AS last_access_time,
datetime(f.mtime,'unixepoch') AS last_modified_time,
datetime(f.ctime,'unixepoch') AS last_status_change_time,
u.username AS file_owner,
u.uuid AS SID,
f.file_version,
authenticode.subject_name,
authenticode.result, 
'3CX DesktopApp - Files on Disk' AS query
FROM file f
LEFT JOIN users u ON f.uid = u.uid
LEFT JOIN hash h ON f.path = h.path
LEFT JOIN authenticode USING (path)
WHERE f.path like 'c:\users\%\appdata\local\programs\3cxdesktopapp\app\ffmpeg.dll'
OR f.path like 'c:\users\%\appdata\local\programs\3cxdesktopapp\app\d3dcompiler%' 
OR f.path like 'c:\users\%\appdata\local\programs\3cxdesktopapp\3CXDesktopApp.exe'
OR f.path like 'C:\Users\%\AppData\Local\Programs\3CXDesktopApp\Update.exe'
OR f.path like 'c:\ProgramData\3CXPhone\'