/******************************** Sophos.com/RapidResponse **********************************\
| DESCRIPTION                                                                                |
| Looks for suspicious request patterns in Exchange servers that fits the commands identified|
| in the Exchange SSRF vulnerability that allows a attacker to execute arbitrary Powershell  |
| on the server.                                                                             |
|                                                                                            |
|  REFERENCE                                                                                 |
| https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-        |
| vulnerabilities-in-microsoft-exchange-server/                                              |
|                                                                                            |
| Author: The Rapid Response Team                                                            |
| github.com/SophosRapidResponse                                                             |
\********************************************************************************************/

-- GET a list of files
WITH File_List AS (SELECT path,filename FROM file WHERE directory LIKE 'C:\inetpub\logs\LogFiles\W3SVC%')

-- Grep the list of files
SELECT
    f.path as Path,
    f.filename as Filename,
    (SELECT 
    CAST(GROUP_CONCAT(DISTINCT(regex_match(g.line,'(\s200\s|\s302\s|\s401\s)',0))||CHAR(10)) AS text)
	FROM grep g 
	WHERE g.pattern IN ('/autodiscover/autodiscover.json') AND g.path = f.path 
	) As success_code,
(   SELECT 
	CAST(GROUP_CONCAT(g.line,CHAR(10)) AS TEXT) 
	FROM grep g 
	WHERE g.pattern IN ('/autodiscover/autodiscover.json') AND g.path = f.path 
	) As Line
FROM File_List f
WHERE f.filename LIKE '%.log'
AND success_code != ''
AND Line LIKE '%powershell%'