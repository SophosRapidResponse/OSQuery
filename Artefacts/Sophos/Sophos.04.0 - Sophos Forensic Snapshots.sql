/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List devices that have Sophos forensic snapshot available                      |
|                                                                                |
| REFERENCE:                                                                     |
| https://support.sophos.com/support/s/article/KB-000038358?language=en_US       |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
CASE 
	WHEN directory LIKE '%Forensic Snapshots' THEN 'custom-generated'
	WHEN directory LIKE '%Saved Data' THEN 'threat detection'
END AS 'From', 
filename,
path,
directory,
round((size * 10e-7) ,2)|| ' ' || 'MB' AS 'size', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(btime,'unixepoch')) AS creation_time,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS modified_time,
'File' AS source, 
'Sophos.04.0' AS Query
FROM file
WHERE directory IN ('C:\ProgramData\Sophos\Endpoint Defense\Data\Forensic Snapshots', 'C:\ProgramData\Sophos\Endpoint Defense\Data\Saved Data')
	AND filename LIKE '%snapshot%.tgz'
ORDER BY btime DESC