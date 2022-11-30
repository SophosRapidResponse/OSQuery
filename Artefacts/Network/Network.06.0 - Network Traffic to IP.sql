/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets a sum of all traffic (bytes and MB) going to a particular IP              |
| The query also bring information about the process, cmdline and user associated|
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
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(time,'unixepoch')) AS date_time,
    sophos_pid,
    destination,
    (SUM(data_sent)) AS total_data_sent_bytes,
    round(SUM(data_sent)*10e-7,2) || ' MB' AS total_data_sent_MB
FROM 
    sophos_network_journal
WHERE
    destination = '$$ip$$'
    AND data_sent > 0
    AND time >= $$start_time$$
    AND time <= $$end_time$$
GROUP BY date_time, sophos_pid
)

SELECT
    date_time,
    sophos_process_journal.process_name,
    sophos_process_journal.cmd_line,
    sophos_pid,
    destination,
    total_data_sent_bytes,
    total_data_sent_MB,
    sophos_process_journal.sid,
    u.username,
    'Network/Process/User Journals' AS Data_Source,
    'Network traffic to specific IP' AS Query 
FROM 
    total_data_sent_ip
JOIN sophos_process_journal USING (sophos_pid)
LEFT JOIN users u ON sophos_process_journal.sid = u.uuid