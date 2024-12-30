/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Looks for the Office diagnostic log file. Payloads for CVE-2022-30190          |
| ('Follina') are in this log file.                                              |
|                                                                                |
| REFERENCE                                                                      |
| https://twitter.com/nas_bench/status/1531718490494844928                       |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH File_List AS (
    SELECT 
    path,
    filename, 
    btime,
    mtime 
    FROM file 
    WHERE (path LIKE 'C:\Users\%\AppData\Local\Diagnostics\%%' AND filename = 'PCW.debugreport.xml')
    OR (path LIKE 'C:\Users\%\AppData\Local\Diagnostics\%%' AND filename = 'PCW.debugreport.xml') )

SELECT
    f.path as Path,
    f.filename as Filename,
    datetime(f.btime,'unixepoch') AS creation_time,
    datetime(f.mtime,'unixepoch') AS modified_time,
    (SELECT 
	CAST(GROUP_CONCAT(g.line,CHAR(10)) AS TEXT) 
	FROM grep g 
	WHERE g.pattern IN (CHAR(0),CHAR(10),CHAR(32)) AND g.path = f.path 
	) As File_content,
    'File/Grep' AS Data_Source,
    'Office.02.0' AS Query 
FROM File_List f
WHERE File_content != '' 
ORDER BY creation_time DESC