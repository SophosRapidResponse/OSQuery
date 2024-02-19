/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query detects possible webshell files (.JSP, .WAR) in \webapps folder.     |
|                                                                                |
| IMPORTANT                                                                      |
| This folder also stores legitimate .JSP, .WAR files. Please correlate the      |
| results with the date the files were written to disk, file hashes or any other |
| detection on the machine                                                       |
|                                                                                |
| REFERENCE:                                                                     |
| -  https://www.rapid7.com/blog/post/2022/04/22/opportunistic-exploitation-of-  |
|     wso2-cve-2022-29464/                                                       |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
f.path AS Path,
f.directory AS Directory,
f.filename AS Filename,
f.size AS Size,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.btime,'unixepoch')) AS 'First_Created_On_Disk(btime)',
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(f.mtime,'unixepoch')) AS 'Last_Modified(mtime)',
h.sha256 AS SHA256,
f.attributes AS Attributes,
'Potential webshell' AS Potential_web_shell,
'File/Hash' AS Data_Source,
'WSO2 - webshells' AS Query
FROM file f
JOIN hash h ON f.path = h.path
WHERE
(f.path LIKE 'C:\Ellucian\%\repository\deployment\server\webapps\%\%' 
OR f.path LIKE 'C:\Ellucian\%\%\repository\deployment\server\webapps\%\%'
OR f.path LIKE 'C:\Program Files\WSO2\%\%\repository\deployment\server\webapps\%\%')
AND (filename LIKE '%.jsp' OR filename LIKE '%.war')