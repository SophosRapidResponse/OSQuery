/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identify Run or RunOnce registry keys associated with 3CX Desktop Application  |
|                                                                                |
| REFERENCE                                                                      |
| https://news.sophos.com/en-us/2023/03/29/3cx-dll-sideloading-attack/           |
| https://www.3cx.com/blog/news/desktopapp-security-alert/                       |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
path, 
data, 
type, 
strftime('%Y-%m-%d %H:%M:%S',datetime(mtime,'unixepoch')) AS modified_time,
'3CXDesktopApp - Run Keys' AS Query
FROM registry 
WHERE (key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Run'
OR key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\RunOnce'
OR key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
OR key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\RunServices'
OR key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
OR key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
OR Key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
OR key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices'
OR key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
OR key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx')
AND data LIKE '%3CXDesktop%'

