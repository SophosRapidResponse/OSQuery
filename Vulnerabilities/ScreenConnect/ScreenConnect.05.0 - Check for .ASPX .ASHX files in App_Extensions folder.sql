/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Detect potential exploitation of CVE-2024-1708 on a machine hosting a           |
| ScreenConnect server by looking for .ASPX and .ASHX files written in the        |
| \ScreenConnect\App_Extensions folder.                                           |
|                                                                                 |
| https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-      |
| screenconnect-authentication-bypass                                             |
|                                                                                 |
| Author: The Rapid Response Team | Lee Kirkpatrick                               |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/

SELECT 
f.path, 
f.filename, 
f.size, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) AS 'Last_Status_Change(ctime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) AS 'Last_Accessed(atime)', 
h.sha256,
'file' AS data_source,
'ScreenConnect.05.' AS query
FROM file f 
JOIN hash h ON f.path = h.path 
WHERE 
f.path LIKE 'C:\Program Files (x86)\ScreenConnect\App_Extensions\%.as%x' -- this is the default location but can be changed at installation 

