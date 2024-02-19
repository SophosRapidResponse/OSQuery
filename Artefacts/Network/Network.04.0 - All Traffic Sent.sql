/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets a sum of all traffic (in bytes and MB) captured by the network journal    |
| daily, and a sum of all data sent to external IPs. Can detect traffic spikes   |
| that might indicate data exfiltration. However, it might generate false        |
| positives for traffic related to IPv6.                                         |
|                                                                                |
| VARIABLES                                                                      |
| - start_time: (date)                                                           |
| - end_time: (date)                                                             |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH
  total_data_sent_external AS (
  SELECT
    strftime('%m-%d-%Y',datetime(time,'unixepoch')) AS Day,
    (SUM(data_sent)) AS total_data_sent_external_bytes,
    round(SUM(data_sent)*10e-7,2) || ' MB' AS total_data_sent_external_MB
    
FROM 
    sophos_network_journal
WHERE
    (destination NOT LIKE '192.168.%.%'
    AND destination NOT GLOB '172.1[6-9].*.*'
    AND destination NOT GLOB '172.2[0-9].*'
    AND destination NOT GLOB '172.3[0-1].*'
    AND destination NOT LIKE '10.%'
    AND destination NOT LIKE '127.%')
    AND time >= $$start_time$$
    AND time <= $$end_time$$
GROUP BY Day
),
  
total_data_sent  AS(  
SELECT
    strftime('%m-%d-%Y',datetime(time,'unixepoch')) AS Day,
    (SUM(data_sent)) AS total_data_sent_bytes,
    round(SUM(data_sent)*10e-7,2)|| ' MB' AS total_data_sent_MB
FROM 
    sophos_network_journal
WHERE
   time >= $$start_time$$
   AND time <= $$end_time$$
GROUP BY Day
)

SELECT
    tbl1.Day,
    total_data_sent_bytes,
    total_data_sent_MB,
    total_data_sent_external_bytes,
    total_data_sent_external_MB,
    'Network Journal' AS Data_Source,
    'Network.04.0 - All Traffic Sent' AS Query 
FROM 
    total_data_sent tbl1 JOIN total_data_sent_external tbl2 ON tbl1.Day = tbl2.Day