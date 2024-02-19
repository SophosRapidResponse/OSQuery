/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all WMI entries from the four WMI tables: wmi_cli_event_consumers,        |
| wmi_event_filters, wmi_filter_consumer_binding, wmi_script_event_consumers     |
| TACTIC: persistence                                                            |
|                                                                                |
| VARIABLES                                                                      |
| - value (type: string) - string to search for                                  |
|                                                                                |
| TIP                                                                            |
| If you want to bring back everything use wildcard % for the value variable     |
|                                                                                |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
'WMI CommandLine EventConsumer' AS data_source,
name, 
command_line_template, 
executable_path,
NULL as query, 
NULL as consumer, 
NULL as filter, 
NULL AS script_file_name,
NULL AS script_text,
'WMI.01.0' AS query_name
FROM wmi_cli_event_consumers 
WHERE name LIKE '$$value$$' OR command_line_template LIKE '$$value$$'

UNION ALL 

SELECT
'WMI EventsFilters' AS data_source,
name, 
NULL as command_line_template, 
NULL AS executable_path,
query, 
NULL as consumer, 
NULL as Filter, 
NULL AS script_file_name,
NULL AS script_text,
'WMI.01.0' AS query_name
FROM wmi_event_filters 
WHERE name LIKE '$$value$$' OR query LIKE '$$value$$'

UNION ALL 

SELECT 
'WMI Binding' AS data_source,
NULL as Name, 
NULL as command_line_template, 
NULL AS executable_path,
NULL as Query, 
consumer, 
filter, 
NULL AS script_file_name,
NULL AS script_text,
'WMI.01.0' AS query_name
FROM wmi_filter_consumer_binding 
WHERE consumer LIKE '$$value$$' OR filter LIKE '$$value$$'

UNION ALL 

SELECT
'WMI ActiveScript EventConsumer' AS data_source,
name, 
NULL as command_line_template, 
NULL AS executable_path,
NULL as query, 
NULL as consumer, 
NULL as filter, 
script_file_name,
script_text,
'WMI.01.0' AS query_name
FROM wmi_script_event_consumers
WHERE name LIKE '$$value$$' OR script_file_name LIKE '$$value$$' OR script_text LIKE '$$value$$'
