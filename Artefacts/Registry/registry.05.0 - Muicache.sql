/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| When an application starts, Windows extracts some information from the resource|
| section of the PE file and stores it in a registry key known as the MuiCache.  |
| This artifact can be evidence that a program ran.                              |
|                                                                                |
| It's worth noticing that data in the Muicache can be easily deleted.           |
|                                                                                |
| VARIABLES                                                                      |
| - username   (type: string)                                                    |
| - sid        (type: string)                                                    |
| - start_time (type: date)                                                      |
| - end_time   (type: date)                                                      |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH
ApplicationCompany AS (
    SELECT
    REGEX_MATCH(name,'.*(?=\.)',0) AS app_path, 
    data AS company_name,
    regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid
    FROM registry
    WHERE path LIKE 'HKEY_USERS\%\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache\%.ApplicationCompany'
),

FriendyApp AS
(
SELECT 
    mtime,
    REGEX_MATCH(name,'.*(?=\.)',0) AS app_path,
    data AS app_name,
    regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid,
    path,
    key
    FROM registry
    WHERE path LIKE 'HKEY_USERS\%\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache\%.FriendlyAppName'
)

SELECT 
    datetime(fa.mtime,'unixepoch') AS modified_time,
    fa.app_path,
    fa.app_name,
    ac.company_name,
    u.username,
    fa.sid,
    fa.key, 
    'MUIcache' AS query
FROM FriendyApp fa
LEFT JOIN  users u ON fa.sid = u.uuid
LEFT JOIN ApplicationCompany ac ON (fa.app_path = ac.app_path AND fa.sid = ac.sid)
WHERE u.username LIKE '$$username$$' 
    AND fa.sid LIKE '$$sid$$'
    AND fa.app_name != ''
    AND fa.mtime >= $$start_time$$ 
    AND fa.mtime <= $$end_time$$
ORDER BY modified_time DESC 