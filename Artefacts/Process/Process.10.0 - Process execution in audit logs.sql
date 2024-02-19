/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists process events on Linux and macOS systems via Audit/OpenBSM subsystems   |
| within a time range                                                            |
|                                                                                |
| VARIABLES                                                                      |
| -start_time (type: date)                                                       |
| -end_time (type: date)                                                         |
|                                                                                |
| #!PLATFORM_TYPE = linux, macos (10.15 and older)                               |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ', DATETIME(process_events.time, 'unixepoch')) AS execution_time,
    process_events.pid || ':' || process_events.time AS sophos_pid,
    process_events.pid,
    process_events.cmdline,
    process_events.path,
    users.username,
    process_events.uid,
    process_events.mode AS file_permission,
    process_events.cwd AS process_directory,
    strftime('%Y-%m-%dT%H:%M:%SZ', DATETIME(process_events.atime, 'unixepoch')) AS access_time,
    strftime('%Y-%m-%dT%H:%M:%SZ', DATETIME(process_events.mtime, 'unixepoch')) AS modification_time,
    strftime('%Y-%m-%dT%H:%M:%SZ', DATETIME(process_events.ctime, 'unixepoch')) AS metadata_change_time,
    parent AS parent_pid,
    syscall,
    'Process Events' AS data_source,
    'Process.10.0' AS query
FROM process_events
INNER JOIN users ON
    process_events.uid = users.uid
WHERE process_events.time >= '$$start_time$$'
    AND process_events.time <= '$$end_time$$'
    AND path NOT IN ('/usr/bin/awk','/usr/bin/sed','/usr/bin/tr')
