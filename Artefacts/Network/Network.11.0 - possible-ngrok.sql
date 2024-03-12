/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| By default ngrok listens on loopback port 4040                                 |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT DISTINCT
    process.name,
    listening.port,
    listening.address,
    process.pid
FROM
    processes AS process
JOIN
    listening_ports AS listening ON process.pid = listening.pid
WHERE
    port = 4040
    AND address = '127.0.0.1';
