/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check for network traffic, this comes from the Network, IP, DNS and HTTP       |
| journals. The amount of data in these is very large and the query can be slow  |
| to run. If you have IOCs already then you should use 'Network.02.0'.           |
|                                                                                |
| VARIABLES                                                                      |
| begin(date) = datetime of when to start hunting                                |
| days(string) = how many days to search through                                 |
|                                                                                |
| TIP                                                                            |
| You can do multiple days, but you are asking for a lot of data so if it fails  |
| do one day at a time.                                                          |
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
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(snj.start_time,'unixepoch')) AS date_time,
 spj.path AS path,
 spj.cmd_line AS cmd_line,
 snj.sophos_pid AS sophos_pid, 
 CAST (spj.process_name AS TEXT) process_name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(snj.process_start_time,'unixepoch')) AS process_start_time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
 spj.sid AS sid,
 spj.parent_sophos_pid AS sophos_parent_pid, 
 CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_path,
 '' AS destination_device,
 snj.destination AS destination_ip_url,
 snj.destination_port AS destinatin_port,
 '' AS source_device,
 snj.source AS source_ip_url,
 snj.source_port AS source_port,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(snj.start_time,'unixepoch')) AS connection_start,
 snj.data_sent AS bytes_sent,
 snj.data_recv AS bytes_received,
 spj.sha256 AS sha256,
 spj.file_size AS file_size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) first_created_on_disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) last_changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) last_modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) last_accessed,
 'Network Journal/Process Journal/File/Users' AS data_source,
 'Network.01.0' AS query 
 
FROM for
 LEFT JOIN sophos_network_journal snj ON snj.time >= for.x and snj.time <= for.x+1200  
 JOIN sophos_process_journal spj ON snj.sophos_pid = spj.sophos_pid
 

UNION ALL
/***********************************************************************************\
|                                sophos_dns_journal                                 |
\***********************************************************************************/
SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sdj.process_start_time,'unixepoch')) AS date_time,
 spj.path AS path,
 spj.cmd_line AS cmd_line,
 sdj.sophos_pid AS sophos_pid, 
 CAST (spj.process_name AS TEXT) process_name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
 spj.sid AS sid,
 spj.parent_sophos_pid AS sophos_parent_pid, 
 '' AS parent_path,
 '' AS destination_device,
 sdj.name AS destination_ip_url,
 '' AS destinatin_port,
 '' AS source_device,
 '' AS source_ip_url,
 '' AS source_port,
 '' AS connection_start,
 '' AS bytes_sent,
 '' AS bytes_received,
 spj.sha256 AS sha256,
 spj.file_size AS file_size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) first_created_on_disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) last_changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) last_modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) last_accessed,
 'DNS Journal/Process Journal/File/Users' AS data_source,
 'Network.01.0' AS query

FROM for
 LEFT JOIN sophos_dns_journal sdj ON sdj.time >= for.x and sdj.time <= for.x+1200  
 JOIN sophos_process_journal spj ON sdj.sophos_pid = spj.sophos_pid
 

UNION ALL
/***********************************************************************************\
|                                sophos_http_journal                                |
\***********************************************************************************/
SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(shj.process_start_time,'unixepoch')) AS date_time,
 spj.path AS path,
 spj.cmd_line AS cmd_line,
 shj.sophos_pid AS sophos_pid, 
 CAST (spj.process_name AS TEXT) process_name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.process_start_time,'unixepoch')) AS process_start_time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
 spj.sid AS sid,
 spj.parent_sophos_pid AS sophos_parent_pid, 
 '' AS parent_path,
 '' AS destination_device,
 shj.url AS destination_ip_url,
 shj.destination_port AS destinatin_port,
 '' AS source_device,
 '' AS source_ip_url,
 shj.source_port AS source_port,
 '' AS connection_start,
 '' AS bytes_sent,
 '' AS bytes_received,
 spj.sha256 AS Sha256,
 spj.file_size AS file_size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) first_created_on_disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) last_changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) last_modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) last_accessed,
 'HTTP Journal/Process Journal/File/Users' AS data_source,
 'Network.01.0' AS query

FROM for
 LEFT JOIN sophos_http_journal shj ON shj.time >= for.x and shj.time <= for.x+1200  
 JOIN sophos_process_journal spj ON shj.sophos_pid = spj.sophos_pid
 

UNION ALL
/***********************************************************************************\
|                                sophos_ip_journal                                  |
\***********************************************************************************/
SELECT 
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sij.process_start_time,'unixepoch')) AS date_time,
 spj.path AS path,
 spj.cmd_line AS cmd_line,
 sij.sophos_pid AS sophos_pid, 
 CAST (spj.process_name AS TEXT) process_name,
 strftime('%Y-%m-%dT%H:%M:%SZ',datetime(sij.process_start_time,'unixepoch')) AS process_start_time, 
 CASE WHEN spj.end_time = 0 THEN '' ELSE strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spj.end_time,'unixepoch')) END AS process_end_time, 
 CAST ( (Select u.username from users u where spj.sid = u.uuid) AS text) username,
 spj.sid AS sid,
 spj.parent_sophos_pid AS sophos_parent_pid, 
 CAST ( (Select spj2.path from sophos_process_journal spj2 where spj2.sophos_pid = spj.parent_sophos_pid) AS text) parent_path,
 '' AS destination_device,
 sij.destination AS destination_ip_url,
 sij.destination_port AS destinatin_port,
 '' AS source_device,
 sij.source AS source_ip_url,
 sij.source_port AS source_port,
 '' AS connection_start,
 '' AS bytes_sent,
 '' AS bytes_received,
 spj.sha256 AS Sha256,
 spj.file_size AS file_size, 
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = spj.path) AS text) first_created_on_disk,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) from file f where f.path = spj.path) AS text) last_changed,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) from file f where f.path = spj.path) AS text) last_modified,
 CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) from file f where f.path = spj.path) AS text) last_accessed,
 'IP Journal/Process Journal/File/Users' AS data_source,
 'Network.01.0' AS query
 
FROM for
 LEFT JOIN sophos_ip_journal sij ON sij.time >= for.x and sij.time <= for.x+1200  
 JOIN sophos_process_journal spj ON sij.sophos_pid = spj.sophos_pid