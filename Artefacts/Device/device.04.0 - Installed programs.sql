/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists installed programs.                                                      |
|                                                                                |
| VARIABLES                                                                      |
| name(string) = name of the application                                         |
| install_location(filepath) = path of where the application was installed from  |
|                                                                                |
| TIP                                                                            |
| If you want to bring back everything use % for each variable                   |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
name,
version,
install_location,
install_source,
publisher,
uninstall_string,
install_date,
'Programs' AS Data_Source,
'Device.04.0' AS Query  
FROM programs
WHERE name LIKE '$$name$$' 
AND install_location LIKE '$$install_location$$'