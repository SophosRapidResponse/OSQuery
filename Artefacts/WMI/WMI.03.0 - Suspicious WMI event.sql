/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Hunts for suspicious WMI Consumers (CommandLine and ActiveScript)               |
| TACTIC: persistence                                                             |
|                                                                                 |
| If an event of interest is found the event filter should be determined          |
|                                                                                 |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\********************************************************************************/


SELECT
    wcec.name,
    wcec.command_line_template,
    NULL AS scripting_engine,
    wcec.executable_path,
    NULL AS 'script_file_name',
    NULL AS 'script_text',
    wcec.class,
    wcec.relative_path,
    'WMI Commandline EventConsumer' AS data_source,
    'WMI.03.0' AS Query
FROM wmi_cli_event_consumers wcec
WHERE (wcec.command_line_template LIKE '%.exe%'
    OR wcec.command_line_template LIKE '%cmd%'
    OR wcec.command_line_template LIKE '%.dll%'
    OR wcec.command_line_template LIKE '%powershell%'
    OR wcec.command_line_template LIKE '%.vbs%'
    OR wcec.command_line_template LIKE '%.eval%'
    OR wcec.command_line_template LIKE '%.ps1%')
    AND wcec.command_line_template NOT LIKE '%KernCap.vbs%' 


UNION ALL

SELECT
    wsec.name,
    NULL AS command_line_template,
    wsec.scripting_engine,
    NULL AS executable_path,
    wsec.script_file_name,
    wsec.script_text,
    wsec.class,
    wsec.relative_path,
    'WMI ActiveScript EventConsumer' AS data_source,
    'WMI.03.0' AS Query
FROM wmi_script_event_consumers wsec 
WHERE (wsec.script_text LIKE '%.exe%'
    OR wsec.script_text LIKE '%.dll%'
    OR wsec.script_text LIKE '%ActiveXObject%'
    OR wsec.script_text LIKE '%ScriptText%'
    OR wsec.script_text LIKE '%.js%'
    OR wsec.script_text LIKE '%.vbs%')
    AND wsec.name NOT IN ('DellCommandPowerManagerPolicyChangeEventConsumer')