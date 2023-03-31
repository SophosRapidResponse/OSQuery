/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists machines that have 3CX Desktop App installed on Windows                  |
| The query also checks whether the version number is: 18.12.407 & 18.12.416     |
| which were impacted by the recent security issue                               |
|                                                                                |
| REFERENCE                                                                      |
| https://www.3cx.com/blog/news/desktopapp-security-alert/                       |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
name,
version,
CASE
   WHEN version LIKE '18.12.407%' THEN 'True'
   WHEN version LIKE '18.12.416%' THEN 'True'
   ELSE NULL
END AS impacted_version,
install_location,
install_source,
publisher,
uninstall_string,
CASE
   WHEN install_date != '' 
   THEN substr(Install_Date, 0, 5) || '-' || substr(Install_Date, 5, 2) || '-' || substr(Install_Date, 7, 2)
   END AS Install_Date,
'Programs' AS Data_Source,
'Installed 3CX Destopt APP' AS Query  
FROM programs
WHERE name LIKE '%3CX Desktop App%' 