/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detects a possible LSASS dump using LSASS Shtinkering.                         |
| TACTIC: Credential Access                                                      |
|                                                                                |
| When this technique is used we can see artifacts in the following locations:   |
|                                                                                |
| - Windows Event log Application EID 1000 - when the application is lsass.exe   |
| and the faulting module is unknown                                             |
| - Windows error logs WER for lsass.exe when faulting module is not specified   |
| - CrashDump for the lsass process                                              |
|                                                                                |
| REFERENCE:                                                                     |
| https://github.com/deepinstinct/Lsass-Shtinkering                              |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime,
    provider_name AS Provider_Name, 
    eventid AS EventID,
    regex_split(JSON_EXTRACT(data, '$.EventData.Data'),',',0) AS Faulting_Application,
    regex_split(JSON_EXTRACT(data, '$.EventData.Data'),',',10) AS Faulting_App_Path,
    regex_split(JSON_EXTRACT(data, '$.EventData.Data'),',',3) AS Faulting_Module,
    regex_split(JSON_EXTRACT(data, '$.EventData.Data'),',',11) AS Faulting_Module_Path,
    JSON_EXTRACT(data, '$.EventData.Data') AS raw_data,
    '-' AS Path,
    '-' AS Size,
    '-' AS Created_On_Disk,
    '-' AS Last_Modified_Time,
    '-' AS WER_Report,
    '-' AS SHA256,
    'EVTX' AS Data_Source,
    'EVTX.04.0 ' AS Query 
FROM sophos_windows_events 
WHERE source = 'Application'
    AND eventid = 1000
    AND LOWER(Faulting_Application) = 'lsass.exe'
    AND (LOWER(Faulting_Module) = 'unknown' OR LOWER(Faulting_Module_Path) LIKE '%unknown%')

UNION 

SELECT
    '-' AS Datetime, 
    '-' AS Provider_Name,
    '-' AS EvendID,
    '-' AS Faulting_Application,
    '-' AS Faulting_App_Path,
    '-' AS Faulting_Module,
    '-' AS Faulting_Module_Path,
    '-' AS raw_data,
    f.path AS Path,
    f.size AS Size,
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'Created_On_Disk', 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified_Time', 
    CASE WHEN filename LIKE '%.wer' THEN 'Check in the .WER file if faulting module is not specified'
    WHEN filename LIKE '%.dmp' THEN 'lsass .dmp found for process running as NT AUTHORITY\SYSTEM'
    END AS Details,
    h.sha256 AS SHA256,
    'File\Hash' AS Data_Source,
    'EVTX.04.0' AS Query
FROM file f 
JOIN hash h ON f.path = h.path
WHERE f.path LIKE 'C:\ProgramData\Microsoft\Windows\WER\ReportArchive\%_lsass%\Report.wer'
    OR f.path LIKE 'C:\Windows\system32\config\systemprofile\AppData\Local\CrashDumps\lsass.exe%'




