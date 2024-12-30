/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Lists all processes with open network connections. It also collects additional  |
| information about the event such as the user who triggers the process, if it's  |
| still on disk, and file hashes.                                                 |
|                                                                                 |
| TIP                                                                             |
| If you want to bring all data from closed/open connection, please remove first  |
| instruction after the WHERE and enable the second instruction by removing the   |
| comment (--)                                                                    |
|                                                                                 |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


SELECT
    CAST (STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(processes.start_time, 'unixepoch')) AS TEXT) Datetime, 
    processes.pid || ':' || processes.start_time AS sophos_pid,
    CAST (processes.name AS TEXT) process_name,
    CAST (processes.cmdline AS TEXT) cmdline,
    CAST (processes.path AS TEXT) path,
    process_open_sockets.local_port,
    CAST(process_open_sockets.remote_address AS TEXT) AS remote_address,
    process_open_sockets.remote_port,
    CAST (process_open_sockets.state AS TEXT) state,
    users.uid,
    users.username,
    CASE WHEN on_disk = 1 THEN 'True'
    ELSE 'False' END AS is_on_disk,
    parent AS parent_pid,
    (SELECT hash.sha256 FROM hash WHERE processes.path = hash.path) AS process_sha256,
    'Processes/Open_sockets/users' AS Data_Source,
    'processes with Open Sockets' AS query
FROM processes
JOIN process_open_sockets USING (pid)
LEFT JOIN users USING (uid)
WHERE
    process_open_sockets.state IN ('ESTABLISHED','LISTEN')
    --process_open_sockets.state != ''
GROUP BY remote_address
