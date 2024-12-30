/******************************** Sophos.com/RapidResponse **********************************\
| DESCRIPTION                                                                                |
| Searches for suspicious request patterns on Exchange servers that align with commands      |
| associated with the Exchange SSRF vulnerability. This vulnerability allows attackers to    |
| execute arbitrary PowerShell commands on the server.                                       |
|                                                                                            |
|  REFERENCE                                                                                 |
| https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-        |
| vulnerabilities-in-microsoft-exchange-server/                                              |
|                                                                                            |
| Author: The Rapid Response Team                                                            |
| github.com/SophosRapidResponse                                                             |
\********************************************************************************************/

-- GET a list of files
WITH File_List AS (
	SELECT path, filename 
	FROM file 
	WHERE directory LIKE 'C:\inetpub\logs\LogFiles\W3SVC%'
)

-- Grep the list of files
SELECT
f.path as Path,
f.filename as Filename,
(SELECT 
CAST(GROUP_CONCAT(DISTINCT(regex_match(g.line,'(\s200\s|\s302\s|\s401\s)',0))||CHAR(10)) AS text)
FROM grep g 
WHERE g.pattern IN ('/autodiscover/autodiscover.json') AND g.path = f.path 
) As success_code,
(SELECT 
CAST(GROUP_CONCAT(g.line,CHAR(10)) AS TEXT) 
FROM grep g 
WHERE g.pattern IN ('/autodiscover/autodiscover.json') AND g.path = f.path 
) As Line,
'EVTX' AS data_source,
'Exchange.02.0' AS Query
FROM File_List f
WHERE f.filename LIKE '%.log'
AND success_code != ''
AND Line LIKE '%powershell%'