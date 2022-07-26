/**************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                      |
| The query looks for Office server cache key in the registry. There are legitimate|
| situations where office documents make web requests and cache is logged on. The  |
| presence of a URL only means it was contacted, not that it was used in an attack |
|                                                                                  |
| Version: 1.0                                                                     |
| Author: The Rapid Response Team | Lee Kirkpatrick                                |
| github.com/SophosRapidResponse                                                   |
\**********************************************************************************/

SELECT 
    path As Path,
    regex_match(name,'(www|http:|https:)+[^\s]+[\w]',0) AS URL, 
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS Modified_time,
    u.username,
    regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS Sid,
    'Registry' AS Data_Source,
    'Office Server Cache' AS Query
FROM registry JOIN users u ON sid = u.uuid
WHERE URL IS NOT NULL
    AND (key LIKE 'HKEY_CURRENT_USER\SOFTWARE\Microsoft\Office\%\Common\Internet\Server Cache' 
    OR key LIKE 'HKEY_USERS\%\SOFTWARE\Microsoft\Office\%\Common\Internet\Server Cache')