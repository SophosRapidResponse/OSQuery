/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets a list of all compressed archives accessed and/or extracted by a user.    |
| It parses data from the HKEY_USERS registry according to the product used to   |
| compress/extract files. TACTIC: Collection                                     |
|                                                                                |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team |Elida Leite                                   |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH RECURSIVE
Sequence(x) AS (VALUES ( 1 ) UNION ALL SELECT x+1 FROM Sequence WHERE x < (SELECT MAX(LENGTH(REPLACE(data,'00',''))/2) FROM registry WHERE key LIKE 'HKEY_USERS\%\Software\7-Zip\%' AND name IN ('ArcHistory','PathHistory') ))

SELECT
STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(mtime, 'unixepoch')) AS last_time_modified,
'7-zip' AS Product,
CASE
   WHEN name = 'ArcHistory' THEN 'Compressed File'
   WHEN name = 'PathHistory' THEN 'Extracted File'
   ELSE NULL
END AS Status,
(SELECT (WITH Characters(c) AS (SELECT CHAR(int) FROM sequence,hex_to_int WHERE hex_string = '0x'||substring(REPLACE(data,'00',''),x*2-1,2)) SELECT CAST(REPLACE(GROUP_CONCAT(c),',','') AS VARCHAR) FROM Characters)) AS File,
u.username AS user,
regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid,
path,
'registry.02.0' AS query
FROM registry
LEFT JOIN users u ON sid = u.uuid
WHERE key LIKE 'HKEY_USERS\%\Software\7-Zip\%' AND name IN ('ArcHistory','PathHistory')

UNION ALL

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) as last_time_modified,
'Winzip' AS product,
CASE
   WHEN path LIKE '%extract%' THEN 'Extracted Location'
   WHEN path LIKE '%filemenu%' THEN 'Compressed File'
   ELSE NULL
END AS Status,
data AS File,
u.username AS user,
regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid,
path,
'registry.02.0' AS query
FROM registry
LEFT JOIN users u ON sid = u.uuid
WHERE path LIKE 'HKEY_USERS\%\Software\Nico Mak Computing\WinZip\filemenu\%' 
   OR path LIKE 'HKEY_USERS\%\Software\Nico Mak Computing\WinZip\extract\extract'

UNION ALL

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) as last_time_modified,
'WinRAR' AS product,
CASE
   WHEN path LIKE '%ExtrPath%' THEN 'Extracted Location'
   WHEN path LIKE '%ArcHistory%' THEN 'Compressed File'
   WHEN path LIKE '%ArcName%' THEN 'Compressed File'
   ELSE NULL
END AS Status,
data AS File,
u.username AS user,
regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid,
path,
'registry.02.0' AS query
FROM registry
LEFT JOIN users u ON sid = u.uuid
WHERE (path LIKE 'HKEY_USERS\%\Software\WinRAR\ArcHistory\%' 
OR path LIKE 'HKEY_USERS\%\Software\WinRAR\DialogEditHistory\ExtrPath\%'
OR path LIKE 'HKEY_USERS\%\Software\WinRAR\DialogEditHistory\ArcName\%')
