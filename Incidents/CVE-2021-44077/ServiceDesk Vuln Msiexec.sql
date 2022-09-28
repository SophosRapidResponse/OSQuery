/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Checks if exploitation against an unauthenticated remote code execution (RCE)  |
| vulnerability affecting ServiceDesk Plus versions up to 11305 occurred when a  |
| malicious actor uploads an executable named msiexec.exe via a request to the   |
| REST API.                                                                      |
|                                                                                |
| REFERENCE                                                                      |
| https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44077                  |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/



SELECT
   f.path AS Path,
   f.filename AS Filename,
   f.size AS Size,
   CASE WHEN f.filename LIKE 'msiexec.exe' THEN 'Possible explotation of CVE-2021-44077' END AS Details,
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)',
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)',
   h.sha256 AS SHA256,
   f.attributes AS Attributes,
   'File/Hash' AS Data_Source,
   'ServiceDesk Vuln' AS Query
FROM file f
JOIN hash h ON f.path = h.path
WHERE
   (f.path LIKE 'C:\%\ManageEngine\ServiceDesk\bin\%' 
   OR f.path LIKE '%\ManageEngine\ServiceDesk\bin\%')
   AND filename LIKE '%.exe' 