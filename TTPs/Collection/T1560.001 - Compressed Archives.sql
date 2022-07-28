/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets a list of all compressed archives accessed and/or extracted by a user     |
| It parses data from the HKEY_USERS registry according to the product used to   |
| compress/extract files.                                                        |
| The query currently is limited to 7-zip, Winzip, and Winrar                    |
|                                                                                |
| IMPORTANT NOTE                                                                 |
| - 7-Zip results will show the file in hex encode. To quickly transform the data|
| to ASCII format the analyst can use tools such as CyberChef. The recipe can be |
| the following:                                                                 |
|                                                                                |
| From_Hex('Auto')                                                               |
| Remove_null_bytes()                                                            |
|                                                                                |
| - The dates in WinRAR results will show the last modification in registry      |
|                                                                                |
| VARIABLES                                                                      |
| - username (string) - wildcard % can be used to get everything                 |
| - filename (string) - wildcard % can be used to get everything                 |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team |Elida Leite                                   |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) as Modified_Time,
   CASE 
   WHEN path LIKE '%7-Zip%' THEN '7-zip'
   WHEN path LIKE '%Winzip%' THEN 'Winzip'
   WHEN path LIKE '%WinRAR%' THEN 'WinRAR'
   ELSE '' END AS Product,
   CASE
   WHEN name = 'ArcHistory' THEN 'Compressed File'
   WHEN name = 'PathHistory' THEN 'Extracted Location'
   WHEN path LIKE '%extract%' THEN 'Extracted Location'
   WHEN path LIKE '%filemenu%' THEN 'Compressed File'
   WHEN path LIKE '%ExtrPath%' THEN 'Extracted Location'
   WHEN path LIKE '%ArcHistory%' THEN 'Compressed File'
   WHEN path LIKE '%ArcName%' THEN 'Compressed File'
   ELSE '' END AS Status,
   data AS File,
   regex_match(path,'(S-[0-9]+(-[0-9]+)+)', '') AS sid, 
   u.username AS user,
   path AS registry_path, 
   'High' As Potential_FP_chance,
   'Registry/Users' AS Data_Source,
   'T1560.001 - Compressed Archives' AS Query
FROM registry
JOIN users u ON sid = u.uuid
WHERE(
      ((key LIKE 'HKEY_USERS\%\Software\7-Zip\Compression' OR key LIKE 'HKEY_USERS\%\Software\7-Zip\Extraction') AND name IN ('ArcHistory','PathHistory'))
      OR (path LIKE 'HKEY_USERS\%\Software\Nico Mak Computing\WinZip\filemenu\%' OR path LIKE 'HKEY_USERS\%\Software\Nico Mak Computing\WinZip\extract\extract_')
      OR (path LIKE 'HKEY_USERS\%\Software\WinRAR\ArcHistory\%' OR path LIKE 'HKEY_USERS\%\Software\WinRAR\DialogEditHistory\ExtrPath\%' OR path LIKE 'HKEY_USERS\%\Software\WinRAR\DialogEditHistory\ArcName\%')
      )    
   AND File LIKE '$$filename$$' 
   AND u.username LIKE '$$username$$'
ORDER BY Modified_Time DESC
   


   

   
   
   