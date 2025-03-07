/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query aggregates the startup_items, services, scheduled_tasks, and drivers |
| tables.                                                                        |
|                                                                                |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
'Startup Items' AS data_source,
si.name AS Name,
si.path AS Path,
si.args AS Arguments,
NULL AS Description,
si.source AS Directory,
CAST ((SELECT auth.result FROM authenticode auth WHERE si.path = auth.path) AS Text) code_signing,
si.status AS Status,
NULL AS start_type,
si.username AS Username,
'Autostart Execution' AS Query
FROM startup_items si

UNION ALL

SELECT
'Scheduled Task' AS data_source,
st.name AS Name,
st.path AS Path,
st.action AS Arguments,
NULL AS Description,
NULL AS Directory,
NULL AS Code_Signing,
st.state AS Status,
NULL AS Start_Type,
NULL AS Username,
'Autostart Execution' AS Query
FROM scheduled_tasks st

UNION ALL

SELECT
'Services' AS data_source,
svc.name AS Name,
CONCAT(svc.path, CHAR(10), svc.module_path) AS Path,
NULL AS Arguments,
svc.description AS Description,
NULL AS Directory,
NULL AS Code_Signing,
svc.status AS Status,
svc.start_type AS Start_Type,
svc.user_account AS Username,
'Autostart Execution' AS Query
FROM services svc

UNION ALL

SELECT DISTINCT
'Drivers' AS data_source,
drv.description AS Name,
drv.image AS Path,
NULL AS Arguments,
drv.description AS Description,
drv.driver_key AS Directory,
CASE WHEN drv.signed = 1 THEN 'signed' ELSE 'unsigned' END AS Code_Signing,
NULL AS Status,
NULL AS Start_Type,
NULL AS Username,
'Autostart Execution' AS Query
FROM drivers drv