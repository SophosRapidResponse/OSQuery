/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Identify the IP addresses that the ScreenConnect application running on machines|
| is connecting to. these IP addresses can be utilized in external tools like     |
| Shodan.io and Censys.io to assess if the ScreenConnect server corresponding to  |
| these endpoints is vulnerable to CVE-2024-1709 and CVE-2024-1708.               |
|                                                                                 |
| Query type: Data Lake                                                           |
| Author: MDR Team                                                                |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


WITH split_pids AS (
    SELECT
        x2.new_pid,
        x1.*
    FROM
        xdr_data AS x1
    CROSS JOIN
        UNNEST(SPLIT(x1.sophos_pids, ',')) AS x2(new_pid)
    WHERE
        x1.query_name = 'sophos_ips_windows'
),
 
full_list AS (
    SELECT
        x1.meta_hostname AS ep_name,
        x1.query_name AS table_name,
        x2.time AS date_time,
        x2.username AS user_name,
        x2.parent_name AS parent_process_name,
        x2.name AS process_name,
        SUBSTRING( x2.cmdline FROM POSITION('&h=' IN x2.cmdline) FOR POSITION('&p=' IN x2.cmdline) - POSITION('&h=' IN x2.cmdline) ) AS instance_url,
        x2.cmdline AS cmd_line,
        x2.sophos_pid AS sophos_pid,
        x2.parent_sophos_pid AS parent_sophos_pid,
        x2.sha256,
        CASE CAST(x1.query_name = 'sophos_ips_windows' AS INT)
            WHEN 1 THEN x1.source_ip
            ELSE REGEXP_REPLACE(x1.source_ips, ',', CHR(10))
        END AS local_ip,
        x1.port AS local_port,
        CASE CAST(x1.query_name = 'sophos_ips_windows' AS INT)
            WHEN 1 THEN x1.destination_ip
            ELSE REGEXP_REPLACE(x1.destination_ips, ',', CHR(10))
        END AS remote_ip,
        x1.destination_port AS remote_port,
        x1.protocol AS protocol,
        x2.path,
        x2.ml_score,
        x2.pua_score,
        x2.global_rep,
        x2.local_rep,
        x2.parent_path
    FROM
        xdr_data AS x2
    RIGHT JOIN split_pids AS x1 ON x2.query_name = 'running_processes_windows_sophos'
    WHERE
    x1.new_pid = x2.sophos_pid
 
)
SELECT
    ARRAY_JOIN(ARRAY_AGG(DISTINCT ep_name), CHR(10)) AS ep_list,
    COUNT(DISTINCT ep_name) AS ep_count,
    table_name,
    COUNT(DISTINCT sophos_pid) AS instances,
    process_name,
    path,
    cmd_line,
    DATE_FORMAT(FROM_UNIXTIME(MIN(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS first_seen,
    DATE_FORMAT(FROM_UNIXTIME(MAX(date_time)), '%Y-%m-%dT%H:%i:%SZ') AS last_seen,
    user_name,
    instance_url,
    parent_process_name,
    parent_path,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT local_ip), CHR(10)) AS local_ip_list,
    local_port,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT remote_ip), CHR(10)) AS remote_ip_list,
    remote_port,
    protocol,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT sophos_pid), CHR(10)) AS sophos_pid_list,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT parent_sophos_pid), CHR(10)) AS parent_sophos_pid_list,
    sha256,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    'ScreenConnect.02' AS query
FROM 
    full_list
WHERE 
    LOWER(path) LIKE LOWER('%screenconnect%')
GROUP BY
    table_name,
    user_name,
    instance_url,
    parent_process_name,
    process_name,
    cmd_line,
    local_port,
    remote_port,
    protocol,
    sha256,
    path,
    ml_score,
    pua_score,
    global_rep,
    local_rep,
    parent_path
ORDER BY last_seen DESC