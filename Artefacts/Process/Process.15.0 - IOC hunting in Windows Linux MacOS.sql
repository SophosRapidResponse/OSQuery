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
| - sophos_pid (type: SophosPID)                                                  |
|                                                                                 |
| TIP                                                                             |
| If you want to bring all data, please use wildcard (%) for the variables        |
|                                                                                 |
| Query Type: Datalake                                                            |
| Author: The Rapid Response Team | Elida Leite                                   |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


WITH user_table AS ( 
    SELECT
        _users.username AS user_name,
        _users.meta_hostname AS user_host,
        _users.uid AS user_uid,
        _users.uuid AS user_uuid
    FROM
        xdr_data AS _users
    WHERE
        _users.query_name = 'user_accounts'
        AND LOWER(_users.username) LIKE LOWER('$$username$$')
),
 
full_list AS (
    SELECT
        linux_processes.meta_hostname AS ep_name,
        linux_processes.time AS date_time,
        CAST('-' AS varchar) AS parent_process_name,
        linux_processes.name AS process_name,
        user_table.user_name AS user_name,
        linux_processes.cmdline AS cmd_line,
        linux_processes.pids || ':' || CAST(linux_processes.time AS varchar) AS sophos_pid,
        CAST('-' AS varchar) AS parent_sophos_pid,
        linux_processes.sha256 AS sha256,
        linux_processes.path AS path,
        CAST('0' AS integer) AS ml_score,
        CAST('0' AS integer) AS pua_score,
        CAST('0' AS integer) AS global_rep,
        CAST('0' AS integer) AS local_rep,
        linux_processes.gid AS gid,
        CAST('-' AS varchar) AS sid,
        linux_processes.uid AS uid,
        linux_processes.euid AS euid,
        linux_processes.egid AS egid,
        CAST('-' AS varchar) AS parent_path,
        CAST('-' AS varchar) AS process_signed,
        CAST('-' AS varchar) AS original_filename,
        CAST('-' AS varchar) AS product_name
    FROM
        xdr_data AS linux_processes
    INNER JOIN
        user_table
        ON
            user_table.user_host = linux_processes.meta_hostname
            AND user_table.user_uid = linux_processes.uid
    WHERE
        linux_processes.query_name = 'running_processes_linux_events'
        AND LOWER(linux_processes.cmdline) LIKE LOWER('$$cmd_line$$')
        AND LOWER(linux_processes.meta_hostname) LIKE LOWER('$$hostname$$')
        AND sophos_pid LIKE '$$sophos_pid$$'
 
    UNION ALL
 
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
        CAST('0' AS bigint) AS gid,
        CAST (user_table.user_uuid AS VARCHAR) AS sid,
        CAST('0' AS bigint) AS uid,
        CAST('0' AS bigint) AS euid,
        CAST('0' AS bigint) AS egid,
        windows_processes.parent_path AS parent_path,
        windows_processes.is_process_file_signed AS process_signed,
        windows_processes.original_filename AS original_filename,
        windows_processes.product_name AS product_name
    FROM
        xdr_data AS windows_processes
    INNER JOIN
        user_table
        ON
            user_table.user_host = windows_processes.meta_hostname
            AND user_table.user_name = windows_processes.username
    WHERE
        windows_processes.query_name = 'running_processes_windows_sophos'
        AND LOWER(windows_processes.username) LIKE LOWER('$$username$$')
        AND LOWER(windows_processes.meta_hostname) LIKE LOWER('$$hostname$$')
        AND LOWER(windows_processes.cmdline) LIKE LOWER('$$cmd_line$$')
        AND windows_processes.sophos_pid LIKE '$$sophos_pid$$'
 
    UNION ALL
 
    SELECT
        osx_processes.meta_hostname AS ep_name,
        osx_processes.time AS date_time,
      CAST('-' AS varchar) AS parent_process_name,
        osx_processes.name AS process_name,
        user_table.user_name AS user_name,
        osx_processes.cmdline AS cmd_line,
        CAST(osx_processes.pid AS varchar) AS sophos_pid,
        CAST(osx_processes.parent AS varchar) AS parent_sophos_pid,
        osx_processes.sha256 AS sha256,
        osx_processes.path AS path,
        CAST('0' AS integer) AS ml_score,
        CAST('0' AS integer) AS pua_score,
        CAST('0' AS integer) AS global_rep,
        CAST('0' AS integer) AS local_rep,
        osx_processes.gid,
        CAST('-' AS varchar) AS sid,
        osx_processes.uid,
        osx_processes.euid,
        osx_processes.egid,
        CAST('-' AS varchar) AS parent_path,
        CAST('-' AS varchar) AS process_signed,
        CAST('-' AS varchar) AS original_filename,
        CAST('-' AS varchar) AS product_name
    FROM xdr_data AS osx_processes
    INNER JOIN
        user_table
        ON
            user_table.user_host = osx_processes.meta_hostname
            AND user_table.user_uid = osx_processes.uid
    WHERE
        osx_processes.query_name = 'running_processes_osx_events'
        AND osx_processes.meta_hostname LIKE '$$hostname$$'
        AND LOWER(osx_processes.cmdline) LIKE LOWER('$$cmd_line$$')

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
    sid,
    parent_process_name,
    parent_path,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT sophos_pid), CHR(10)) AS sophos_pid_list,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT parent_sophos_pid), CHR(10)) AS parent_sophos_pid_list,
    sha256,
    process_signed,
    gid,
    uid,
    euid,
    egid,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    original_filename,
    product_name
FROM
    full_list
GROUP BY
    user_name,
    parent_process_name,
    process_name,
    cmd_line,
    sha256,
    path,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    gid,
    uid,
    sid,
    euid,
    egid,
    parent_path,
    process_signed,
    original_filename,
    product_name
ORDER BY last_seen DESC