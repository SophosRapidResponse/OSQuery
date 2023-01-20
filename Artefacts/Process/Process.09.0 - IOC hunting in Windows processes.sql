/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Lists activity of all processes during a pre-determined period of time.         |
| Activity can be filtered by a specific hostname, command-line, username, and    |
| Sophos PID.                                                                     |
|                                                                                 |
| VARIABLES                                                                       |
| - hostname (type: Device Name )                                                 |
| - cmd_line (type: String)                                                       |
| - username (type: Username)                                                     |
| - pid      (type: SophosPID)                                                    |
|                                                                                 |
| TIP                                                                             |
| If you want to bring all data, please use wildcard (%) for the variables        |
|                                                                                 |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


WITH windows_processes AS (
    SELECT
        windows_processes.meta_hostname AS ep_name,
        windows_processes.time AS date_time,
        windows_processes.parent_name AS parent_process_name,
        windows_processes.name AS process_name,
        windows_processes.username AS user_name,
        windows_processes.cmdline AS cmd_line,
        windows_processes.sophos_pid AS sophos_pid,
        windows_processes.parent_sophos_pid AS parent_sophos_pid,
        windows_processes.sha256 AS sha256,
        windows_processes.path AS path,
        windows_processes.ml_score AS ml_score,
        windows_processes.pua_score AS pua_score,
        windows_processes.global_rep AS global_rep,
        windows_processes.local_rep AS local_rep,
        windows_processes.parent_path AS parent_path, 
        'Process.09.0 - IOC hunting in Windows processes'
    FROM
        xdr_data AS windows_processes
    WHERE
        windows_processes.query_name = 'running_processes_windows_sophos'
        AND windows_processes.meta_hostname LIKE '$$hostname$$'
        AND LOWER(windows_processes.cmdline) LIKE LOWER('$$cmd_line$$')
        AND windows_processes.username LIKE LOWER('$$username$$')
        AND windows_processes.sophos_pid LIKE LOWER('$$pid$$')
)

SELECT
    ARRAY_JOIN(ARRAY_AGG(DISTINCT ep_name), CHR(10)) AS ep_list,
    COUNT(DISTINCT ep_name) AS ep_count,
    process_name,
    path,
    cmd_line,
    DATE_FORMAT(FROM_UNIXTIME(MIN(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS first_seen,
    DATE_FORMAT(FROM_UNIXTIME(MAX(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS last_seen,
    user_name,
    parent_process_name,
    parent_path,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT sophos_pid), CHR(10)) AS sophos_pid_list,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT parent_sophos_pid), CHR(10)) AS parent_sophos_pid_list,
    sha256,
    ml_score,
    pua_score,
    global_rep,
    local_rep
FROM
    windows_processes
GROUP BY
    process_name,
    cmd_line,
    user_name,
    path,
    parent_process_name,
    parent_path,
    sha256,
    ml_score,
    pua_score,
    global_rep,
    local_rep
ORDER BY last_seen DESC