/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detailed information for each device, including hostname, operating system name|
| and version, and timezone.                                                     |
|                                                                                |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
name,
version,
build,
platform,
codename,
arch,
strftime('%Y-%m-%dT%H:%M:%SZ', datetime(install_date,'unixepoch')) AS Install_Date,
time.local_timezone,
patch,
'os_version' AS Data_Source,
'Device Details' AS Query 
FROM os_version 
LEFT JOIN time