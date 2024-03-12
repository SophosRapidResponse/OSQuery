/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Recent RDP sessions from NTUSER.DAT                                            |
|                                                                                |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    data AS 'Remote RDP Address',
    regex_match(path, '(S-[0-9]+(-[0-9]+)+)', '') AS sid,
    u.username
FROM
    registry
LEFT JOIN
    users u ON sid = u.uuid
WHERE
    key LIKE 'HKEY_USERS\%\SOFTWARE\Microsoft\Terminal Server Client\Default'
    AND data <> '';
