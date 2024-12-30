/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                     |
| Lists URLs accessed by a user directly via Internet Explorer and Edge. The      |
| timestamps aren't reliable.                                                     |
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
'registry' AS source,
'Browser.05.0' AS query
FROM registry 
LEFT JOIN  users u ON sid = u.uuid
WHERE path LIKE 'HKEY_USERS\%\Software\Microsoft\Internet Explorer\TypedURLs\%'
    AND u.username LIKE '$$username$$' 
    AND sid LIKE '$$user_sid$$'
ORDER BY modified_time DESC 




