/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| View recently opened MS Office documents                                       |
|                                                                                |
| VARIABLES                                                                      |
| - IOC: allow searches for filename, username, or sid.                          |
|                                                                                |
| TIP:                                                                           |
|   If want to get everything use wildcard %                                     |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
mru.path as Filename,
strftime('%Y-%m-%dT%H:%M:%SZ', datetime(mru.last_opened_time,'unixepoch')) AS Last_Opened_Time,
CAST ( (Select strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) from file f where f.path = mru.path) AS text) First_Created_On_Disk,
h.sha256,
CAST ( (Select u.username from users u where sid = u.uuid) AS text) Username,
mru.sid,
mru.application,
mru.version,
'Office_MRU/User/Hash' AS Data_Source,
'Office_MRU.01.0' AS Query 
from office_mru mru 
LEFT JOIN hash h ON mru.path = h.path
WHERE filename LIKE '%$$IOC$$%' OR Username = '$$IOC$$' OR mru.sid = '$$IOC$$'