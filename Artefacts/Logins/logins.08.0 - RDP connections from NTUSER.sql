/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identifies remote RDP connections by analyzing MRU entries from the NTUSER.DAT |
| registry hive which provides details on systems recently accessed via Remote   |
| Desktop Connection.                                                            |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
strftime('%Y-%m-%dT%H:%M:%SZ', mtime,'unixepoch') AS last_modified_time,
data AS 'Remote RDP Address',
regex_match(path, '(S-[0-9]+(-[0-9]+)+)', '') AS sid,
u.username,
key,
'registry' AS data_source,
'logins.08.0' AS query
FROM
    registry
LEFT JOIN
    users u ON sid = u.uuid
WHERE
    key LIKE 'HKEY_USERS\%\SOFTWARE\Microsoft\Terminal Server Client\Default'
    AND data <> '';