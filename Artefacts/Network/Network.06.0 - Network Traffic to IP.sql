/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets a sum of all traffic (bytes and MB) going to a specified IP. The query    |
| also returns information about the process, command line, and user associated  |
| with the traffic.                                                              |
|                                                                                |
| VARIABLE                                                                       |
| - start_time (type: DATE)                                                      |
| - end_time   (type: DATE)                                                      |
| - ip         (type: STRING)                                                    |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/



WITH
  total_data_sent_ip AS (
  SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(MIN(time),'unixepoch')) AS first_occurrance,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(MAX(time),'unixepoch')) AS last_occurrance,
    sophos_pid,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(process_start_time,'unixepoch')) AS process_startime,
    destination,
    destination_port,
    SUM(data_sent) AS total_data_sent_bytes,
    ROUND(SUM(data_sent) * 1e-6, 2) AS total_data_sent_MB,
    SUM(data_recv) AS total_data_received_bytes   
FROM 
    sophos_network_journal
WHERE
    destination = '$$ip$$'
    AND data_sent > 0
    AND time BETWEEN $$begin$$ AND $$end$$
GROUP BY sophos_pid, destination, destination_port
)

SELECT
    first_occurrance,
    last_occurrance,
    process_startime,
    sophos_process_journal.process_name,
    sophos_process_journal.cmd_line,
    sophos_pid,
    destination,
    destination_port,
    total_data_sent_bytes,
    total_data_sent_MB,
    total_data_received_bytes,
    sophos_process_journal.sid,
    u.username,
    'network_journals' AS Data_Source,
    'Network.06.0' AS Query 
FROM 
    total_data_sent_ip
JOIN sophos_process_journal USING (sophos_pid)
LEFT JOIN users u ON sophos_process_journal.sid = u.uuid