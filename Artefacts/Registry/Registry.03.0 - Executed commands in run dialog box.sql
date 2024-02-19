/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Lists all the most recent commands run in the Run dialog (RunMRU) for a specific|
| username. Use it to find evidence of execution and/or lateral movement.         |
|                                                                                 |
| The MRUList key holds a list that can contain up to 26 commands indicated with a|
| letter from a to z. The order in which the commands were executed is from the   |
| most recent to the least.                                                       |
|                                                                                 |
| VARIABLE                                                                        |
| - username (type: STRING)                                                       |
|                                                                                 |
| If you want to bring back everything use the wildcard % for username            |
|                                                                                 |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\********************************************************************************/

SELECT 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS last_modified_time,
    REPLACE(data,'\1','') AS command,
    name,
    u.username,
    regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid,
    path,
    'registry/user' AS source,
    'registry.03.0' AS query
FROM registry 
LEFT JOIN  users u ON sid = u.uuid
WHERE path LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\%'
AND name <> 'MRUList'
AND u.username LIKE '$$username$$'