/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                     |
| Lists all the most recent commands executed in the Run Dialog box (RunMRU) for  |
| each user (NTUSER), which can be used to find evidence of application execution |
| lateral movement.                                                               |
|                                                                                 |
| The MRUList key holds a list that can contain up to 26 commands indicated with a|
| letter from a to z. The order in which the commands were executed is from the   |
| most recent to the least.                                                       |
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
    'Executed Commands in Run Dialog' AS query
FROM registry 
LEFT JOIN  users u ON sid = u.uuid
WHERE path LIKE 'HKEY_USERS\%\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU\%'
    AND u.username LIKE '$$username$$' 
    AND sid LIKE '$$user_sid$$'