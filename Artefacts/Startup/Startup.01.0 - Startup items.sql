/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all items that load on startup.                                           |
|                                                                                |
| Version: 1.1                                                                   |
| Author: @AltShiftPrtScn & Elida Leite                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
	name AS Startup_name,
	path AS Path,
	args AS Arguments,
	type AS Startup_Login,
	source AS Directory,
	status AS Startup_status,
	username AS Username,
	CASE
	WHEN source = regex_match(source, '^(\/).*$',0) THEN 'Linux/Unix'
	WHEN type LIKE 'systemd%' THEN 'Linux/Unix'
	ELSE 'Windows OS' END AS Operating_System,
	'Startup_items' AS Data_Source,
	'T1547 - Startup Items' AS Query
FROM startup_items
