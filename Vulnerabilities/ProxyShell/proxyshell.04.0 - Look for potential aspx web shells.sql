/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Looks for .ASPX web shells in common locations.                                |
|                                                                                |
| NOTE                                                                           |
| Many of the results from this query will be legitimate files, look at the      |
| the times they were created and combine with other ProxyShell queries to       |
| verify.                                                                        |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn & Sophos MTR                                           |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
	f.path AS Path,
	f.filename AS Filename,
	f.size AS Size,
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)', 
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.ctime,'unixepoch')) AS 'Last_Status_Change(ctime)', 
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)', 
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.atime,'unixepoch')) AS 'Last_Accessed(atime)',
	h.sha256 AS SHA256,
	'File/Hash' AS Data_Source,
	'ProxyShell.04.0' AS Query
FROM file f
LEFT JOIN hash h
ON f.path = h.path
WHERE (f.path LIKE 'C:\inetpub\wwwroot\aspnet_client\system_web\%'
	OR f.path LIKE 'C:\inetpub\wwwroot\aspnet_client\%'
	OR f.path LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\%'
	OR f.path LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\auth\%'
	OR f.path LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\current\%'
	OR f.path LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\current\themes\%'
	OR f.path LIKE 'C:\ProgramData\%'
	OR f.path LIKE 'C:\ProgramData\%\%'
) AND (LOWER(filename) LIKE '%.aspx')



