/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets a list of programs that may start in safe mode. The query searches in the |
| Windows Registry for keys created or modified in a specific timeframe.         |
|                                                                                |
| VARIABLES                                                                      |
| -start_time (type: Date)                                                       |
| -end_time (type: Date)                                                         |
|                                                                                |
| https://attack.mitre.org/techniques/T1562/009/                                 |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
'Configured to run on Safe Mode' AS details,
CAST(strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS TEXT) last_modified_time,
key,
CAST(name AS TEXT) AS name,
expand_env(data) As data,
'T1562.010 - Safe Mode Boot' AS query
FROM registry
WHERE key IN (
    'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run',
    'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce')
AND name LIKE '*%'
AND mtime >= $$start_time$$ 
AND mtime <= $$end_time$$

UNION

SELECT 
CASE 
WHEN key LIKE '%\Network' THEN 'Safe Mode with Networking'
ELSE 'Safe Mode'
END AS details,
CAST(strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS TEXT) last_modified_time,
key,
CAST(name AS TEXT) AS name,
expand_env(data) As data,
'T1562.010 - Safe Mode Boot' AS query
FROM registry
WHERE key IN ('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network','HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal')
AND mtime >= $$start_time$$ 
AND mtime <= $$end_time$$