/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all Internet Explorer browser extensions installed on the host.          |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
ie.name,
ie.version,
ie.path,
ie.registry_path,
users.username,
regex_match(ie.registry_path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid,
'browser.06' AS query
FROM ie_extensions AS ie
LEFT JOIN users ON users.uuid = sid
WHERE ie.path IS NOT NULL