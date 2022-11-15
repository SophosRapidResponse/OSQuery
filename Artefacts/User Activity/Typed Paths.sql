/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                     |
| Lists folders accessed by an user directly via the File Explorer path bar       |
|                                                                                 |
| It can expose hidden and commonly accessed locations, including those present on|
| external drives or network shares                                               |
|                                                                                 |
| VARIABLE                                                                        |
| - username (type: STRING)                                                       |
| - user_sid (type: STRING)                                                       |
|                                                                                 |
| If you want to bring back everything use % for username/user_sid                |
|                                                                                 |
| Version: 1.0                                                                    |
| Author: The Rapid Response Team                                                 |
| github.com/SophosRapidResponse                                                  |
\********************************************************************************/

SELECT 
    datetime(mtime,'unixepoch') AS modified_time,
    key, 
    name, 
    data,
    u.username,
    regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid,
    'registry/user' AS source,
    'Typed Paths Explorer' AS query
FROM registry 
LEFT JOIN  users u ON sid = u.uuid
WHERE path LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\%'
    AND u.username LIKE '$$username$$' 
    AND sid LIKE '$$user_sid$$'
ORDER BY modified_time DESC 
