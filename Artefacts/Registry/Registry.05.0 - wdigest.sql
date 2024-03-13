/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Extracts the WDigest registry value                                            |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
CAST(strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS TEXT) Last_Modified,
path AS Path,
name AS Name,
type AS Type,
data AS Data
FROM registry WHERE path LIKE 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest\%' AND Name = 'UseLogonCredential' AND data = '1'
