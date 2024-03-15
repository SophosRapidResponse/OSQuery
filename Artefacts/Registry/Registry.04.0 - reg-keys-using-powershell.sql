/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identified registry keys containing PowerShell                                 |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT *
FROM registry
WHERE
    (key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\%\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\%\%\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\%\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\%\%\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\%\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\%\%\%\%' OR
    key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Run' OR
    key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Run\%' OR
    key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Run\%\%' OR
    key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Run\%\%\%' OR
    key LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Run\%\%\%\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\%' OR
    key LIKE 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\%\%')
    AND
    (data LIKE '%powershell%' OR
    data LIKE '%706f7765727368656c6c%' OR
    data LIKE '%70006F007700650072007300680065006C006C%' OR
    data LIKE '%720065006700730076007200330032%')
    AND NOT data = 'PowerShell';

