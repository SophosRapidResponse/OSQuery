/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query uses several tables associated with a program execution such as:     |
| BAM, Shimcache, Userassist, Prefetch, Shortcuts, and Filesystem tables.        |
| This is a go-to query to quickly identify evidence of a program execution      |
|                                                                                |
| VARIABLE                                                                       |
| - filename: (STRING)  - if want to get everything, please use (%)              |
|                                                                                |
| Example:                                                                       |
| - malware, malware.exe, C:\ProgramData\                                        |
|                                                                                |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
	bam.path As Path,
	'-' AS Filename,
	datetime(bam.last_execution_time,'unixepoch') AS Last_Executed,
	'-' AS Last_Modified,
	'-' AS Creation_Time,
	'-' As Count,
	bam.sid As SID,
	CAST ((SELECT user.username FROM users user WHERE bam.sid = user.uuid) AS Text) Username,
	'BAM' AS Data_Source,
	'TA0002 - Program Execution' As Query
FROM background_activities_moderator as bam
WHERE bam.path like '%$$filename$$%'

UNION

SELECT
	shim.path As Path,
	'-' AS Filename,
	'-' AS Last_Executed,
	datetime(shim.modified_time,'unixepoch') AS Last_Modified,
	'-' AS Creation_Time,
	'-' As Count,
	'-' As SID,
	'-' As Username,
	'Shimcache' AS Data_Source,
	'TA0002 - Program Execution' As Query
FROM shimcache as shim
WHERE shim.path like '%$$filename$$%'

UNION

SELECT
	ua.path as Path,
	'-' AS Filename,
	datetime(ua.last_execution_time,'unixepoch') AS Last_Executed,
	'-' AS Last_Modified,
	'-' AS Creation_Time,
	ua.count As Count,
	ua.sid As SID,
	CAST ((SELECT user.username FROM users user WHERE ua.sid = user.uuid) AS Text) Username,
	'Userassist' AS Data_Source,
	'TA0002 - Program Execution' As Query
FROM userassist as ua
WHERE ua.path like '%$$filename$$%'

UNION

SELECT
	pf.path As Path,
	pf.filename AS Filename,
	datetime(pf.last_run_time,'unixepoch') AS Last_Executed,
	'-' AS Last_Modified,
	'-' Creation_Time,
	'-' As Count,
	'-' As SID,
	'-' As Username,
	'Prefetch' AS Data_Source,
	'TA0002 - Program Execution' As Query
FROM prefetch as pf
WHERE pf.filename like '%$$filename$$%'

UNION

SELECT
	f.path As Path,
	f.filename AS Filename,
	'-' AS Last_Executed,
	datetime(f.mtime,'unixepoch') AS Last_Modified,
	datetime(f.btime,'unixepoch') AS Creation_Time,
	'-' As Count,
	'-' As SID,
	'-' As Username,
	'Filesystem' AS Data_Source,
	'TA0002 - Program Execution' As Query
FROM file as f 
WHERE ((f.directory LIKE 'C:\Users\%\%' OR f.directory IN ('C:\Windows\','C:\ProgramData\','C:\')) AND f.filename like '%$$filename$$%')

UNION

SELECT
	f.path AS Path,
	f.filename AS Filename,
	'-' As Last_Executed,
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS Last_Modified, 
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS Creation_Time, 
	'-' As Count,
	'-' As SID,
	'-' As Username,
	'Recent_Files' AS Data_Source,
	'TA0002 - Program Execution' AS Query
FROM file as f
WHERE f.path LIKE 'C:\Users\%\AppData\Roaming\Microsoft\%\Recent\%$$filename$$%'
	AND filename != '.' 

ORDER BY Last_Executed DESC, Last_Modified DESC