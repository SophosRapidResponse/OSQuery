/******************************* Sophos.com/RapidResponse ********************************\
| DESCRIPTION                                                                             |
| Searches for messages related to downloads of suspicious file types on an Exchange      |
| Server, which could indicate a web shell deployment attempt. The query searches for the |
| string \"Download failed and temporary file\" in the                                    |
| C:\\Program Files\\Microsoft\\Exchange Server\\V15\\Logging\\OABGeneratorLog log file.  |
|                                                                                         |
| REFERENCE                                                                               |
| CVE-2021-26858                                                                          |
| https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-     |
| vulnerabilities-in-microsoft-exchange-server/                                           |
| https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers   |
|                                                                                         |
| Author: The Rapid Response Team                                                         |
| github.com/SophosRapidResponse                                                          |
\*****************************************************************************************/

WITH File_List AS (
    SELECT path, filename 
    FROM file 
    WHERE directory LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog'
)

SELECT
f.path,
f.filename,
(SELECT 
CAST(GROUP_CONCAT(g.line,CHAR(10)) AS TEXT) 
FROM grep g 
WHERE g.pattern IN ('Download failed and temporary file') 
AND g.path = f.path ) As Line,
(SELECT 
CAST(GROUP_CONCAT(DISTINCT(regex_match(g.line,'\s.*(\.js|\.jsp|\.aspx|\.asmx|\.php|\.asax|\.cfm|\.shtml)\s', 0)) || CHAR(10)) AS text)
FROM grep g 
WHERE g.pattern IN ('Download failed and temporary file') 
AND g.path = f.path ) As possible_webshell_match,
'EVTX' AS data_source,
'Exchange.01.0' AS Query
FROM File_List f
WHERE f.filename LIKE '%.log'
AND Line != ''