/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detailed information about the hostname, operating system name, version, and   |
| timezone for each device.                                                      |
|                                                                                |
|                                                                                |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
    name As Name,
    version As Version,
    build As Build,
    platform As Platform,
    codename As Codename,
    arch As Arch,
    strftime('%Y-%m-%dT%H:%M:%SZ', datetime(install_date,'unixepoch')) AS Install_Date,
    time.local_timezone As Local_timezone,
    patch As Patch,
    'os_version' AS Data_Source,
    'Device Details' AS Query 
FROM os_version 
LEFT JOIN time