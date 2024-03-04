/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Atera login IntegratorLogin                                                    |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT 
path,
name, 
data,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS last_modified_time
FROM registry
WHERE
key LIKE 'HKEY_LOCAL_MACHINE\SOFTWARE\ATERA Networks\AlphaAgent'
AND name = 'IntegratorLogin'
