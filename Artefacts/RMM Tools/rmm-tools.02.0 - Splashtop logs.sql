/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Extracts targeted information from the Splashtop log file, such as IP addresses|
| of client logged in and file transfer events.                                  |
|                                                                                |
| File location on disk:                                                         |
| C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\SPLog.txt         |
|                                                                                |
| REFERENCE:                                                                     |
| https://attack.mitre.org/techniques/T1219/                                     |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
grep.path,
file.filename,
grep.pattern, 
CASE 
   WHEN grep.pattern = 'public' THEN REGEX_MATCH(grep.line,'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',0)
   ELSE REGEX_MATCH(grep.line, '(fileName[^,]*)', 1) 
END AS extracted_content,
grep.line AS line, 
'rmm tools.02.0' AS query
FROM file
CROSS JOIN grep USING(path)
WHERE
file.path LIKE 'C:\Program Files (x86)\Splashtop\Splashtop Remote\Server\log\SPLog%'
AND grep.pattern IN ('public','upload','download')