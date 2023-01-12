/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets all file events (creation, deletion, renamed) that occurred in a specific |
| file or directory. The query also provides information about the process linked|
| to the file event as well as the user ID.                                      |                                                                       
|                                                                                |
| Useful to run against the TA working directory or any other folder of interest |
|                                                                                |
| VARIABLE                                                                       |
| - path (type: string)                                                          |
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
sfj.file,
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
AND sfj.time >= $$start_time$$
AND sfj.time <= $$end_time$$





