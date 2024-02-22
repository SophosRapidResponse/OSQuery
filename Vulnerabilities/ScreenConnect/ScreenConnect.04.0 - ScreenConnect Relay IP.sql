/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Identify the IP addresses that the ScreenConnect application running on machines|
| is connecting to. these IP addresses can be utilized in external tools like     |
| Shodan to assess if the ScreenConnect server corresponding to these endpoints   |
| is vulnerable to CVE-2024-1709 and CVE-2024-1708.                               |
|                                                                                 |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/


SELECT DISTINCT
data.meta_hostname AS ep_name,
s.remote_address,
s.remote_port,
data.name,
data.cmdline,
CASE
    WHEN s.remote_address LIKE '192.168.%' THEN 'private_IP'
    WHEN s.remote_address LIKE '172.%' AND CAST(SUBSTR(s.remote_address, 5, 2) AS INTEGER) BETWEEN 16 AND 31 THEN 'private_IP'
    WHEN s.remote_address LIKE '10.%' THEN 'private_IP'
    WHEN s.remote_address LIKE '127.%' THEN 'private_IP'
    ELSE 'public_IP'
END AS ip_classification
FROM xdr_data data
JOIN
    (SELECT remote_address, remote_port, cmdline FROM xdr_data WHERE query_name = 'open_sockets') AS s
ON
    data.cmdline = s.cmdline
'datalake' AS data_source,
'ScreenConnect.04.' AS query
WHERE query_name = 'running_processes_windows_sophos'
AND data.name LIKE 'ScreenConnect.%.exe'
AND (s.remote_address NOT LIKE '192.168.%' OR s.remote_address NOT LIKE '10.%')
AND s.remote_port = 8041