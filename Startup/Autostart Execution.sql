/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query aggregates the tables: Startup_items, services, scheduled_tasks, and |
| drivers                                                                        |
|                                                                                |
| IMPORTANT                                                                      |
| - In the Service results, the column  Path is a junction of the path to service|
| executable and the path to Service DLL.                                        |
|                                                                                |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
	si.name AS Name,
	si.path AS Path,
	si.args AS Arguments,
	'-' As Description,
	si.source AS Directory,
	CAST ((SELECT auth.result FROM authenticode auth WHERE si.path = auth.path) AS Text) code_signing,
	si.status AS Status,
	'-' AS start_type,
	si.username AS Username,
	'Startup Items' AS Data_Source,
	'T1547 - Autostart Execution' AS Query
FROM startup_items si

UNION ALL

SELECT
	name AS Name,
	path AS Path,
	action AS Arguments,
	'-' As Description,
	'-' AS Directory,
	'-' AS code_signing,
	state AS status,
	'-' AS start_type,
	'-' AS Username,
	'Scheduled Task' AS Data_Source,
	'T1547 - Autostart Execution' AS Query
FROM scheduled_tasks

UNION ALL

SELECT
	name As Name,
	CONCAT(path,CHAR(10),module_path) AS Path,
	'-' As Arguments,
	description AS Description,
	'-' AS Directory,
	'-' As code_signing,
	status AS status,
	start_type,
	user_account AS Username,
	'Services' AS Data_Source,
	'T1547 - Autostart Execution' AS Query
FROM services

UNION ALL

SELECT DISTINCT
	description As name,
	image AS path,
	'-' As Arguments,
	description AS Description,
	driver_key AS Directory,
	CASE WHEN signed = 1 THEN 'signed'
	ELSE 'unsigned' END AS code_signing,
	'-' AS status,
	'-' AS start_type,
	'-' AS Username,
	'Drivers' AS Data_Source,
	'T1547 - Autostart Execution' AS Query
FROM drivers
