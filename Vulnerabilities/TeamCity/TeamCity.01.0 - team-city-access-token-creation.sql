/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detects possible TeamCity exploitation - CVE-2024-27198                        |
| Access Token Creation                                                          |                      
|                                                                                |
| Reference: https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and  |
| -cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabili  |
| ties-fixed/                                                                    |
|                                                                                |              
| Query Type: Endpoint                                                           |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
grep.path,
line,
regex_match(grep.line,'\/S*\/?\S*jsp=\S*\.jsp.\S+', 0) as match
FROM file
CROSS JOIN grep ON (grep.path = file.path)
WHERE
file.path LIKE 'C:\TeamCity\logs\teamcity-javaLogging-%.log'
AND match IS NOT NULL
