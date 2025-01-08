/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Checks for network connections in the data from 'sophos_network_journal',      |
| 'sophos_ip_journal', 'sophos_http_journal' and 'sophos_dns_journal'. It        |
| includes information about the associated process and user.                    |
|                                                                                |
| VARIABLES                                                                      |
| begin(date) = datetime of when to start hunting                                |
| days(string) = how many days to search through                                 |
| ioc1(string) = IOC to hunt (IP, URL, Destination Port)                         |
| ioc2(string) = IOC to hunt (IP, URL, Destination Port)                         |
| ioc3(string) = IOC to hunt (IP, URL, Destination Port)                         |
|                                                                                |
| TIP                                                                            |
| If you only want to use one variable put something that wont be found in the   |
| others e.g. zzzzzzzz                                                           |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH for(x) AS (
   VALUES ( (CAST ($$begin$$ AS INT) ) )
   UNION ALL
   SELECT x+1200 FROM for WHERE x < (CAST ($$begin$$ AS INT) + CAST( ($$days$$ * 86400) AS INT))
)

/***********************************************************************************\
|                                sophos_network_journal                             |
\***********************************************************************************/
SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(snj.start_time,'unixepoch')) AS Datetime,
 spj.path AS Path,
 spj.cmd_line AS CMD_line,
 snj.sophos_pid AS Sophos_PID, 
 CAST (spj.process_name AS TEXT) Process_Name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(snj.process_start_time,'unixepoch')) AS Process_Start_Time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS Process_End_Time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) Username,
 spj.sid AS SID,
 spj.parent_sophos_pid AS Sophos_Parent_PID, 
 CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_Path,
 '' AS Destination_Device,
 snj.destination AS Destination_IP_URL,
 snj.destination_port AS Destinatin_Port,
 '' AS Source_Device,
 snj.source AS Source_IP_URL,
 snj.source_port AS Source_Port,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(snj.start_time,'unixepoch')) AS Connection_Start,
 snj.data_sent AS Bytes_Sent,
 snj.data_recv AS Bytes_Received,
 spj.sha256 AS Sha256,
 spj.file_size AS File_Size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) First_Created_On_Disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Accessed,
 'Network Journal/Process Journal/File/Users' AS Data_Source,
 'Network.01.0' AS Query 
 
FROM for
 LEFT JOIN sophos_network_journal snj ON snj.time >= for.x and snj.time <= for.x+1200  
 JOIN sophos_process_journal spj ON snj.sophos_pid = spj.sophos_pid
 
WHERE (snj.destination LIKE '$$ioc1$$' OR snj.destination LIKE '$$ioc2$$' OR snj.destination LIKE '$$ioc3$$') 
OR (snj.destination_port LIKE '$$ioc1$$' OR snj.destination_port LIKE '$$ioc2$$' OR snj.destination_port LIKE '$$ioc3$$') 

UNION ALL
/***********************************************************************************\
|                                sophos_dns_journal                                 |
\***********************************************************************************/
SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sdj.process_start_time,'unixepoch')) AS Datetime,
 spj.path AS Path,
 spj.cmd_line AS CMD_line,
 sdj.sophos_pid AS Sophos_PID, 
 CAST (spj.process_name AS TEXT) Process_Name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS Process_Start_Time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS Process_End_Time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) Username,
 spj.sid AS SID,
 spj.parent_sophos_pid AS Sophos_Parent_PID, 
 '' AS Parent_Path,
 '' AS Destination_Device,
 sdj.name AS Destination_IP_URL,
 '' AS Destinatin_Port,
 '' AS Source_Device,
 '' AS Source_IP_URL,
 '' AS Source_Port,
 '' AS Connection_Start,
 '' AS Bytes_Sent,
 '' AS Bytes_Received,
 spj.sha256 AS Sha256,
 spj.file_size AS File_Size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) First_Created_On_Disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Accessed,
 'DNS Journal/Process Journal/File/Users' AS Data_Source,
 'Network.01.0' AS Query

FROM for
 LEFT JOIN sophos_dns_journal sdj ON sdj.time >= for.x and sdj.time <= for.x+1200  
 JOIN sophos_process_journal spj ON sdj.sophos_pid = spj.sophos_pid
 
WHERE (sdj.name LIKE '$$ioc1$$' OR sdj.name LIKE '$$ioc2$$' OR sdj.name LIKE '$$ioc3$$')


UNION ALL
/***********************************************************************************\
|                                sophos_http_journal                                |
\***********************************************************************************/
SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(shj.process_start_time,'unixepoch')) AS Datetime,
 spj.path AS Path,
 spj.cmd_line AS CMD_line,
 shj.sophos_pid AS Sophos_PID, 
 CAST (spj.process_name AS TEXT) Process_Name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS Process_Start_Time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS Process_End_Time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) Username,
 spj.sid AS SID,
 spj.parent_sophos_pid AS Sophos_Parent_PID, 
 '' AS Parent_Path,
 '' AS Destination_Device,
 shj.url AS Destination_IP_URL,
 shj.destination_port AS Destinatin_Port,
 '' AS Source_Device,
 '' AS Source_IP_URL,
 shj.source_port AS Source_Port,
 '' AS Connection_Start,
 '' AS Bytes_Sent,
 '' AS Bytes_Received,
 spj.sha256 AS Sha256,
 spj.file_size AS File_Size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) First_Created_On_Disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Accessed,
 'HTTP Journal/Process Journal/File/Users' AS Data_Source,
 'Network.01.0' AS Query

FROM for
 LEFT JOIN sophos_http_journal shj ON shj.time >= for.x and shj.time <= for.x+1200  
 JOIN sophos_process_journal spj ON shj.sophos_pid = spj.sophos_pid
 
WHERE (shj.url LIKE '$$ioc1$$' OR shj.url LIKE '$$ioc2$$' OR shj.url LIKE '$$ioc3$$')
OR (shj.destination_port LIKE '$$ioc1$$' OR shj.destination_port LIKE '$$ioc2$$' OR shj.destination_port LIKE '$$ioc3$$')


UNION ALL
/***********************************************************************************\
|                                sophos_ip_journal                                  |
\***********************************************************************************/
SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sij.process_start_time,'unixepoch')) AS Datetime,
 spj.path AS Path,
 spj.cmd_line AS CMD_line,
 sij.sophos_pid AS Sophos_PID, 
 CAST (spj.process_name AS TEXT) Process_Name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sij.process_start_time,'unixepoch')) AS Process_Start_Time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS Process_End_Time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) Username,
 spj.sid AS SID,
 spj.parent_sophos_pid AS Sophos_Parent_PID, 
 CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) Parent_Path,
 '' AS Destination_Device,
 sij.destination AS Destination_IP_URL,
 sij.destination_port AS Destinatin_Port,
 '' AS Source_Device,
 sij.source AS Source_IP_URL,
 sij.source_port AS Source_Port,
 '' AS Connection_Start,
 '' AS Bytes_Sent,
 '' AS Bytes_Received,
 spj.sha256 AS Sha256,
 spj.file_size AS File_Size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) First_Created_On_Disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) Last_Accessed,
 'IP Journal/Process Journal/File/Users' AS Data_Source,
 'Network.01.0' AS Query
 
FROM for
 LEFT JOIN sophos_ip_journal sij ON sij.time >= for.x and sij.time <= for.x+1200  
 JOIN sophos_process_journal spj ON sij.sophos_pid = spj.sophos_pid
 
WHERE (sij.destination LIKE '$$ioc1$$' OR sij.destination LIKE '$$ioc2$$' OR sij.destination LIKE '$$ioc3$$') 
OR (sij.destination_port LIKE '$$ioc1$$' OR sij.destination_port LIKE '$$ioc2$$' OR sij.destination_port LIKE '$$ioc3$$') 