/***************************** Sophos.com/RapidResponse *****************************\
| DESCRIPTION                                                                        |
| Identifies the creation of Alternate Data Streams (ADS) in the filesystem and its  |
| possible manipulation via PowerShell. This artifact can be abused by TAs to hide   |
| malware in the system.                                                             |
|                                                                                    |
| VARIABLES                                                                          |
| - DAY: (STRING) - how many days does the analyst want to look back at logs.        |
|                                                                                    |
|                                                                                    |
| Version: 1.0                                                                       |
| Author: Elida Leite                                                                |
| github.com/SophosRapidResponse                                                     |
\************************************************************************************/


SELECT
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS creation_time,
   spj.cmd_line AS cmd_line,
   '-' As Path,
   '-' As Filename,
   CAST (spj.process_name AS TEXT) process_name,
   spj.sophos_pid AS sophos_PID, 
   CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
   spj.sid AS sid,
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
   CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
   spj.parent_sophos_pid AS sophos_parent_PID,
   CAST ( (Select spj2.process_name from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_process,
   'Process Journal/Users' AS Data_Source,
   'T1564.004 - Hide Artifact NTFS File Attributes' AS Query 
FROM sophos_process_journal spj 
WHERE process_name IN ('powershell.exe', 'powershell_ise.exe', 'cmd.exe')
   AND (cmd_line LIKE '%Get-Item%-stream%' 
   OR cmd_line LIKE '%Set-Item%-stream%' 
   OR cmd_line LIKE '%Remove-Item%-stream%' 
   OR cmd_line LIKE '%Get-ChildItem%-stream%') 
   AND spj.time > STRFTIME('%s','NOW','-$$DAY$$ DAYS')

UNION

SELECT 
   datetime(sfj.creation_time,'unixepoch') As creation_time,
   '-' As cmd_line,
   sfj.path As Path,
   regex_match(sfj.path,'[^\\]+$',0) As Filename,
   spj.process_name As process_name,
   sfj.sophos_pid AS sophos_PID,
   u.username As Username, 
   spj.sid, 
   '-' As  process_start_time,  
   '-' As  process_end_time, 
   '-' As  sophos_parent_PID,
   '-' As  parent_process,
   'Users/Processes/Files Journal' AS Data_Source,
   'T1564.004 Hide Artifact NTFS File Atributes' AS Query
FROM sophos_file_journal sfj
   JOIN sophos_process_journal spj ON spj.sophos_pid = sfj.sophos_pid
   JOIN users u ON u.uuid = spj.sid
WHERE sfj.subject = 'FileBinaryChanges' AND sfj.time > strftime('%s','now','-$$DAY$$ days') AND sfj.event_type IN (0,1,3)
   AND filename LIKE '%:%' 
   AND SPLIT(regex_match(sfj.path,'[^\\]+$',0),':',1) NOT IN ('SmartScreen', 'Zone.Identifier')
GROUP BY sfj.sophos_pid
ORDER BY creation_time DESC