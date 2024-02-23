/*************************** Sophos.com/RapidResponse *****************************\
| DESCRIPTION                                                                      |
| Identifies ScreenConnect Client endpoints which are communicating to Cloud or    |
| On-Prem Servers by utilizing Sophos XDR data from sophos_running_processes and   |
| sophos_ips_windows. Displays column data to identify the communicating endpoints,|
| the timeframe of communication, the remote ScreenConnect instance URL, and remote|
| IP of the ScreenConnect Server accepting the connections. The remote IP of the   |
| ScreenConnect Server can be utilized in external tools like Shodan.io and        |
| Censys.io to assess if the ScreenConnect Server corresponding to these endpoints |
| is vulnerable to CVE-2024-1709 and CVE-2024-1708.                                |
|                                                                                  |
| Query type: Data Lake                                                            |
| Author: MDR Team                                                                 |
| github.com/SophosRapidResponse                                                   |
\**********************************************************************************/


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
        LOWER(x2.name) AS process_name,
        LOWER(x2.original_filename) AS original_filename,
        SUBSTRING( x2.cmdline FROM POSITION('&h=' IN x2.cmdline) FOR POSITION('&p=' IN x2.cmdline) - POSITION('&h=' IN x2.cmdline) ) AS screenconnect_instance_url,
        x2.cmdline AS cmd_line,
        x2.sophos_pid AS sophos_pid,
        CASE
            WHEN x2.destination_ip LIKE '192.168.%' THEN 'private_IP'
            WHEN x2.destination_ip  LIKE '172.%' AND CAST(SUBSTR(x2.destination_ip, 5, 2) AS INTEGER) BETWEEN 16 AND 31 THEN 'private_IP'
            WHEN x2.destination_ip  LIKE '10.%' THEN 'private_IP'
            WHEN x2.destination_ip  LIKE '127.%' THEN 'private_IP'
            ELSE 'public_IP'
        END AS ip_classification,
        x1.destination_ip AS remote_ip,
        x1.destination_port AS remote_port,
        x2.path
    FROM
        xdr_data AS x2
    RIGHT JOIN split_pids AS x1 ON x2.query_name = 'running_processes_windows_sophos'
    WHERE
        x1.new_pid = x2.sophos_pid
)

SELECT
    ARRAY_JOIN(ARRAY_AGG(DISTINCT ep_name), CHR(10)) AS hostname_list,
    COUNT(DISTINCT ep_name) AS host_count,
    DATE_FORMAT(FROM_UNIXTIME(MIN(date_time)), '%Y-%m-%dT%H:%i:%S') AS first_seen,
    DATE_FORMAT(FROM_UNIXTIME(MAX(date_time)), '%Y-%m-%dT%H:%i:%S') AS last_seen,
    process_name,
    screenconnect_instance_url,
    ip_classification,
    ARRAY_JOIN(ARRAY_AGG(DISTINCT remote_ip), CHR(10)) AS screenconnect_server_list,
    remote_port,
    path
FROM 
    full_list
WHERE 
    LOWER(process_name) = 'screenconnect.clientservice.exe'
GROUP BY
    screenconnect_instance_url,
    ip_classification,
    process_name,
    remote_port,
    path
ORDER BY first_seen DESC