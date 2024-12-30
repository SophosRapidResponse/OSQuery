/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets detailed file events for a specific file or directory, such as creation,  |
| deletion, or renaming. This query provides comprehensive information about the |
| associated processes, including process name, command line, and user SID. It's |
| ideal for tracking file activity related to specific processes.                |
|                                                                                |
| VARIABLE                                                                       |
| - path        (type: string)                                                   |
| - start_time  (type: date)                                                     |
| - end_time    (type: date)                                                     |
| - sophos_pid  (type: string)                                                   |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.time,'unixepoch')) AS date_time,
CASE sfj.event_type
    WHEN 0 THEN 'Created'
    WHEN 1 THEN 'Renamed'
    WHEN 2 THEN 'Deleted'
    WHEN 3 THEN 'Modified'
    WHEN 4 THEN 'HardLinkCreated'
    WHEN 5 THEN 'TimestampsModified'
    WHEN 6 THEN 'PermissionsModified'
    WHEN 7 THEN 'OwnershipModified'
    WHEN 8 THEN 'Accessed'
    WHEN 9 THEN 'BinaryFileMapped'
 ELSE '-' END AS event_type,
sfj.path, 
sfj.target_path,
sfj.file_size,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.creation_time,'unixepoch')) AS creation_time,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.last_access_time,'unixepoch')) AS last_access,
sfj.sha256,
CASE sfj.file_type_class
    WHEN 0 THEN 'unknonw'
    WHEN 1 THEN 'directory'
    WHEN 2 THEN 'binary'
    WHEN 3 THEN 'data'
    WHEN 4 THEN 'other' 
END AS file_type,
CASE sfj.file_attributes
    WHEN 1 THEN 'READONLY'
    WHEN 2 THEN 'HIDDEN'
    WHEN 4 THEN 'SYSTEM'
    WHEN 16 THEN 'DIRECTORY'
    WHEN 32 THEN 'ARCHIVE'
    WHEN 64 THEN 'DEVICE'
    WHEN 128 THEN 'NORMAL'
    WHEN 256 THEN 'TEMPORARY'
    ELSE sfj.file_attributes END AS attributes,
spj.process_name,
spj.cmd_line,
sfj.sophos_pid,
spj.sid
FROM sophos_file_journal sfj
JOIN sophos_process_journal spj USING (sophos_pid)
WHERE sfj.path LIKE '$$path$$'
AND sfj.sophos_pid LIKE '$$sophos_pid$$'
AND sfj.time >= $$start_time$$
AND sfj.time <= $$end_time$$





