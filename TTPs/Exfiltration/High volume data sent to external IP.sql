/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets the total amount of outbound traffic (in GB) to an external IP daily      |
| The query's 'data_GB_threshold' variable specifies the data transfer threshold |
| in GB                                                                          |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type: DATE)                                                      |
| - end_time (type: DATE)                                                        |
| - data_GB_threshold  (type: STRING)                                            |
|                                                                                |
| EXAMPLE                                                                        |
| - data_GB_threshold = 5                                                        |
|   Returns all the results when the transfer is over 5 GBs                      |
|                                                                                |
| Author: The Rapid Response Team  | Elida Leite                                 |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH
  total_data_sent_external AS (
  SELECT
    strftime('%m-%d-%Y',datetime(time,'unixepoch')) AS Day,
    sophos_pid,
    round(SUM(data_sent)*10e-10,2) AS total_data_sent_external_GB,
    destination,
    destination_port
FROM 
    sophos_network_journal
WHERE
    (destination NOT LIKE '192.168.%.%'
    AND destination NOT GLOB '172.1[6-9].*.*'
    AND destination NOT GLOB '172.2[0-9].*'
    AND destination NOT GLOB '172.3[0-1].*'
    AND destination NOT LIKE '10.%'
    AND destination NOT LIKE '127.%'
    AND destination NOT LIKE '%::%')
    AND time >= $$start_time$$
    AND time <= $$end_time$$
GROUP BY Day, destination
)  

SELECT
    Day,
    sophos_pid,
    total_data_sent_external_GB,
    destination AS destionation_ip,
    destination_port,
    'Network Journal' AS Data_Source,
    'High volume data sent to external IP' AS Query 
FROM total_data_sent_external 
WHERE total_data_sent_external_GB >= $$data_GB_threshold$$