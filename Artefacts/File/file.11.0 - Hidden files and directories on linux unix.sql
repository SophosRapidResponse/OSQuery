/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists hidden files and directories in the root and user path on Linux and Mac  |
|                                                                                |
| Adversaries can levarage this to hide files and folders anywhere on the system |
| to evade a typical user/system analysis that don't investigate hidden files    |
|                                                                                |
| REFERENCE                                                                      |
| https://attack.mitre.org/techniques/T1564/001/                                 |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    CASE WHEN type = 'regular' THEN 'hidden_files'
    WHEN type = 'directory' THEN 'hidden_directories'
    END AS status,
    filename, 
    file.path, 
    CAST (STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(atime, 'unixepoch')) AS TEXT) accessed_time,
    CAST (STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(ctime, 'unixepoch')) AS TEXT) changed_time, 
    CAST (STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(mtime, 'unixepoch')) AS TEXT) modified_time,
    CASE WHEN type = 'regular' THEN  (SELECT CAST(GROUP_CONCAT(g.line,CHAR(10)) AS TEXT) FROM grep g        
        WHERE g.pattern IN (CHAR(0),CHAR(10),CHAR(32)) AND g.path = file.path)
    ELSE '-' END AS File_content,
    size,
    CAST (hash.sha256 AS TEXT) sha256,
    'File.11.0' AS query
FROM file
JOIN hash ON file.path = hash.path 
WHERE (file.path like '/home/%/.%' 
    OR file.path like '/root/.%'
    OR file.path like '/var/www/.%'
    OR file.path like '/var/tmp/.%'
    OR file.path like '/tmp/.%') 
    AND type IN ('regular', 'directory')
ORDER BY file.mtime DESC