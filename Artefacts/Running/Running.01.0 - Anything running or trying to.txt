/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query aggregates the tables: Startup_items, services, scheduled_tasks,     |
| drivers, processes, logged_in_users looks at the contents of GPO scripts.      |
|                                                                                |
| The purpose os this query is to look for anything that is running, or will     |
| try to run. You can search for filenames, paths, usernames, sids, services,    |
| parts of a command line, or scheduled task argument.                           |
|                                                                                |
| VARIABLE                                                                       |
| IOC (string) - filename, process, cmdline, service, username, sid, task        |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
	'Startup Items' AS Data_Source,
	si.name AS Name,
	si.path AS Path,
	si.args AS Arguments,
	si.username AS Username,
	'-' AS PID,
	CASE WHEN
		si.path = '' THEN '' 
	ELSE
		CAST ((SELECT h.sha256 FROM hash h WHERE si.path = h.path) AS Text)
	END AS SHA256_SID,
	'Running.01.0' AS Query
FROM startup_items si
WHERE 
	Name LIKE '%$$IOC$$%' 
	OR Path LIKE '%$$IOC$$%'
	OR Arguments LIKE '%$$IOC$$%'
	OR Username LIKE '%$$IOC$$%'

UNION ALL

SELECT
	'Scheduled Tasks' AS Data_Source,
	st.name AS Name,
	st.path AS Path,
	st.action AS Arguments,
	'-' AS Username,
	'-' AS PID,
	CASE WHEN
		st.action = '' THEN '' 
	ELSE
		CAST ((SELECT h.sha256 FROM hash h WHERE st.action = h.path) AS Text)
	END AS SHA256_SID,
	'Running.01.0' AS Query	
FROM scheduled_tasks st
WHERE 
	Name LIKE '%$$IOC$$%' 
	OR Path LIKE '%$$IOC$$%'
	OR Arguments LIKE '%$$IOC$$%'
	OR Username LIKE '%$$IOC$$%'

UNION ALL

SELECT
	'Services' AS Data_source,
	s.name AS Name,
	CASE WHEN
		s.module_path = '' THEN s.path 
	ELSE
		s.module_path
	END AS Path,
	s.start_type AS Arguments,
	s.user_account AS Username,
	'-' AS PID,
	CASE WHEN
		s.module_path = '' THEN CAST ((SELECT h.sha256 FROM hash h WHERE s.path = h.path) AS Text) 
	ELSE
		CAST ((SELECT h.sha256 FROM hash h WHERE s.module_path = h.path) AS Text)
	END AS SHA256_SID,
	'Running.01.0' AS Query	
FROM services s
WHERE 
	Name LIKE '%$$IOC$$%' 
	OR Path LIKE '%$$IOC$$%'
	OR Arguments LIKE '%$$IOC$$%'
	OR Username LIKE '%$$IOC$$%'	
	
UNION ALL

SELECT
	'Processes' AS Data_source,
	p.name As Name,
	p.path AS Path,
	p.cmdline AS Arguments,
	'-' AS Username,
	p.pid AS PID,
	CASE WHEN
		p.on_disk = 1 THEN CAST ((SELECT h.sha256 FROM hash h WHERE p.path = h.path) AS Text) 
	ELSE
		'-'
	END AS SHA256_SID,
	'Running.01.0' AS Query	
FROM processes p
WHERE 
	Name LIKE '%$$IOC$$%' 
	OR Path LIKE '%$$IOC$$%'
	OR Arguments LIKE '%$$IOC$$%'
	OR Username LIKE '%$$IOC$$%'		
	
UNION ALL

SELECT
	'Drivers' AS Data_source,
	d.description AS Name,
	d.image AS Path,
	CASE WHEN d.signed = 1 THEN 'Signed'
	ELSE 'Unsigned' END AS Arguments,
	'-' AS Username,
	'-' AS PID,
	CASE WHEN
		d.image = '' THEN '' 
	ELSE
		CAST ((SELECT h.sha256 FROM hash h WHERE d.image = h.path) AS Text) 
	END AS SHA256_SID,
	'Running.01.0' AS Query	
FROM drivers d
WHERE 
	Name LIKE '%$$IOC$$%' 
	OR Path LIKE '%$$IOC$$%'
	OR Arguments LIKE '%$$IOC$$%'
	OR Username LIKE '%$$IOC$$%'
	
UNION ALL

SELECT
	'GPO' AS Data_source,
	f.filename AS Name,
	f.path AS Path,
	CAST ((SELECT g.line FROM grep g WHERE g.path = f.path AND g.pattern LIKE '\') AS Text) AS Arguments,
	'-' AS Username,
	'-' AS PID,
	CASE WHEN
		f.path = '' THEN '' 
	ELSE
		CAST ((SELECT h.sha256 FROM hash h WHERE f.path = h.path) AS Text) 
	END AS SHA256_SID,
	'Running.01.0' AS Query	
FROM file f
WHERE 
	Path LIKE 'C:\Windows\SYSVOL\sysvol\%\Policies\%\%\Scripts\%%'
AND (
	Name LIKE '%$$IOC$$%' 
	OR Path LIKE '%$$IOC$$%'
	OR Arguments LIKE '%$$IOC$$%'
	OR Username LIKE '%$$IOC$$%'
)

UNION ALL

SELECT 
	'Logged In Users' AS Data_Source,
	'-' AS Filename,
	'-' AS Path,
	liu.tty AS Arguments,
	liu.user AS Username,
	'-' AS PID,
	liu.sid AS SHA256_SID,
	'Running.01.0' AS Query	
FROM logged_in_users liu
WHERE 
	Username LIKE '%$$IOC$$%' 
	OR SHA256_SID LIKE '%$$IOC$$%'