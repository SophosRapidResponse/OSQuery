/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Detects possible TeamCity exploitation - CVE-2024-27198                        |
| Token Deleted                                                                  |                      
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
line
FROM file
CROSS JOIN grep ON (grep.path = file.path)
WHERE
(
file.path LIKE 'C:\TeamCity\logs\teamcity-server.log' 
OR
file.path LIKE 'C:\TeamCity\logs\teamcity-activities.log'
)
AND
grep.pattern = 'delete_token_for_user:'
