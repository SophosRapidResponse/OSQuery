/******************************* Sophos.com/RapidResponse ********************************\
| DESCRIPTION                                                                             |
| Detects if exploitation of CVE-2021-27065 occurred by grepping the Exchange log files:  |
| "PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" for evidence of   |
| possible VirtualDirectory set.                                                          |
|                                                                                         |
| If an actor could authenticate with the Exchange server then they could use this vuln   |
| to write a file to any path on the server                                               |
|                                                                                         |                                               
| All Set-<AppName>VirtualDirectory properties should never contain script.               |
| InternalUrl and ExternalUrl should only be valid Uris.                                  |
|                                                                                         |
| REFERENCE                                                                               |
| https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/  | 
|                                                                                         |
| Author: The Rapid Response Team                                                         |
| github.com/SophosRapidResponse                                                          |
\*****************************************************************************************/


WITH File_List AS (SELECT path, filename FROM file WHERE directory LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\Logging\ECP\Server')

SELECT
    f.path AS Path,
    f.filename AS Filename,
	(SELECT 
	CAST(GROUP_CONCAT(g.line,CHAR(10)) AS TEXT) 
	FROM grep g 
	WHERE g.pattern IN ('VirtualDirectory') 
	AND g.path = f.path ) As Line
FROM File_List f
WHERE f.filename LIKE '%.log'
AND Line != ''