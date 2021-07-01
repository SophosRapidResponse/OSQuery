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
CASE
   WHEN install_date != '' 
   THEN substr(Install_Date, 0, 5) || '-' || substr(Install_Date, 5, 2) || '-' || substr(Install_Date, 7, 2)
   END AS Install_Date,
'Programs' AS Data_Source,
'Device.04.0' AS Query  
FROM programs
WHERE name LIKE '$$name$$' AND install_location LIKE '$$install_location$$'