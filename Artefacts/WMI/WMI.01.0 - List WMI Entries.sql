/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all WMI entries from the four WMI tables:                                 |
| wmi_cli_event_consumers                                                        |
| wmi_event_filters                                                              |
| wmi_filter_consumer_binding                                                    |
| wmi_filter_consumer_binding                                                    |
|                                                                                |
| VARIABLES                                                                      |
| string_type(string) - name, command_line_template, query, consumer, filter     |
| value(string) - string to search for                                           |
|                                                                                |
| TIP                                                                            |
| If you want to bring back everything use 'name' for string_type and % for the  |
| value.                                                                         |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
name as Name, 
command_line_template as Command_Line_Template, 
'-' as Query, 
'-' as Consumer, 
'-' as Filter, 
'-' as Binding_Consumer, 
'-' as Binding_Filter,
'WMI Cli Events Consumers' AS Data_Source,
'WMI.01.0' AS Query 
FROM wmi_cli_event_consumers 
WHERE $$string_type$$ LIKE '$$value$$'

UNION ALL 

SELECT
name as Name, 
'-' as Command_Line_Template, 
query as Query, 
'-' as Consumer, 
'-' as Filter, 
'-' as Binding_Consumer, 
'-' as Binding_Filter,
'WMI Events Filters' AS Data_Source,
'WMI.01.0' AS Query  
FROM wmi_event_filters 
WHERE $$string_type$$ LIKE '$$value$$'

UNION ALL 

SELECT 
'-' as Name, 
'-' as Command_Line_Template, 
'-' as Query, 
consumer as Consumer, 
filter as Filter, 
'-' as Binding_Consumer, 
'-' as Binding_Filter,
'WMI Filter Consumer Binding' AS Data_Source,
'WMI.01.0' AS Query  
FROM wmi_filter_consumer_binding 
WHERE $$string_type$$ LIKE '$$value$$'

UNION ALL 

SELECT
'-' as Name, 
'-' as Command_Line_Template, 
'-' as Query, 
'-' as Consumer, 
'-' as Filter, 
consumer as Binding_Consumer, 
filter as Binding_Filter,
'WMI Filter Consumer Binding' AS Data_Source,
'WMI.01.0' AS Query   
FROM wmi_filter_consumer_binding
WHERE $$string_type$$ LIKE '$$value$$'