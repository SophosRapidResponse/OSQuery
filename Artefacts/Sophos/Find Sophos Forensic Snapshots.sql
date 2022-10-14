/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all hosts that have forensic snapshot available                          |
|                                                                                |
|                                                                                |
| REFERENCE:                                                                     |
| https://support.sophos.com/support/s/article/KB-000038358?language=en_US       |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
	CASE WHEN directory LIKE '%Forensic Snapshots' THEN 'Customer-generated'
	WHEN directory LIKE '%Saved Data' THEN 'threat detection'
	END AS 'From', 
	directory,
	filename,
	size, 
	datetime (btime,'unixepoch') AS creation_time,
	datetime (mtime,'unixepoch') AS modified_time,
	'File' AS source, 
	'Find Sophos Snapshots' AS Query
FROM file
WHERE directory IN ('C:\ProgramData\Sophos\Endpoint Defense\Data\Forensic Snapshots', 'C:\ProgramData\Sophos\Endpoint Defense\Data\Saved Data')
	AND filename LIKE '%snapshot%.tgz'
