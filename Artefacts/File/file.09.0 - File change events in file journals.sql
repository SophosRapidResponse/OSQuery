/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Checks for file changes events in 'sophos_file_journal'. There is a large      |
| amount of data available, so limit your 'ioc' variable to specific paths,      |
| if possible. The suggested use of the 'event' variable is '0,1,2,3' for file   |
| created, renamed, modified, and deleted events.                                |
|                                                                                |
| VARIABLES                                                                      |
| begin(date) = datetime of when to start hunting                                |
| end(date) = datetime of when to stop hunting                                   |
| path(filepath) = file path to hunt for                                         |
| event(string) = Comma Seperated File Journal Event Types e.g. 0,1,2,3          |
|           0 = Created                                                          |
|           1 = Renamed                                                          |
|           2 = Deleted                                                          |
|           3 = Modified                                                         |
|           4 = HardLinkCreated                                                  |
|           5 = TimestampsModified                                               |
|           6 = PermissionsModified                                              |
|           7 = OwnershipModified                                                |
|           8 = Accessed                                                         |
|           9 = BinaryFileMapped                                                 |
|                                                                                |
| TIP                                                                            |
| The file journal records a LOT of data, keep the events limited (avoid 8) and  |
| keep the timeframe short.                                                      |
|                                                                                |
| Version: 1.2                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
 CASE sfj.event_type
	WHEN 0 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.creation_time,'unixepoch'))
	WHEN 1 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.change_time,'unixepoch'))
	WHEN 2 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(time,'unixepoch'))
	WHEN 3 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.last_write_time,'unixepoch'))
	WHEN 4 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.change_time,'unixepoch'))
	WHEN 5 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.change_time,'unixepoch'))
	WHEN 6 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.change_time,'unixepoch'))
	WHEN 7 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.change_time,'unixepoch'))
	WHEN 8 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.last_access_time,'unixepoch'))
	WHEN 9 THEN strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.change_time,'unixepoch'))
 ELSE '' END AS date_time,
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
 ELSE '-' END AS description,
 sfj.path AS path, 
 sfj.sophos_pid AS sophos_pid, 
 CAST ( (Select spj.process_name from sophos_process_journal spj where spj.sophos_pid = sfj.sophos_pid) AS text) process_name,
 CAST ( (Select spj.sid from sophos_process_journal spj where spj.sophos_pid = sfj.sophos_pid) AS text) sid,
 sfj.sha256 AS sha256,
 sfj.file_size AS file_size, 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.creation_time,'unixepoch')) AS first_created_on_disk, 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.change_time,'unixepoch')) AS last_changed, 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.last_write_time,'unixepoch')) AS last_modified, 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sfj.last_access_time,'unixepoch')) AS last_accessed,
 'File Journal' AS data_source,
 'File.09.0' AS query
FROM sophos_file_journal sfj 
WHERE sfj.time >= CAST($$begin$$ AS INT) 
AND sfj.time <= CAST($$end$$ AS INT)
AND sfj.path LIKE '$$path$$'
AND sfj.event_type IN ($$event$$) ORDER BY date_time ASC