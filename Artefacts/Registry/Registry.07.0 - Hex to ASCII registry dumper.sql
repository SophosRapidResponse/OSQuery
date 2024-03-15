/*************************** Sophos.com/RapidResponse ************************\
| DESCRIPTION                                                                 |
| The query convert HEX values found in a registry key to ASCII format        |
|                                                                             |
| VARIABLES                                                                   |
| - RegKey (string)                                                           |
|                                                                             |
| EXAMPLE                                                                     |
| RegKey = HKEY_USERS\%\SOFTWARE\7-Zip\FM\FolderHistory                       |
|                                                                             |
| Query Type: Endpoint                                                        |
| Author: Sophos Team                                                         |
| github.com/SophosRapidResponse                                              |
\*****************************************************************************/

WITH RECURSIVE hexd(string,pointer) AS 
(
    SELECT '',(SELECT REPLACE(data,'00','') FROM registry WHERE path LIKE '$$RegKey$$')
   UNION ALL
    SELECT string || char(
  (case substr(pointer,1,1) 
         when 'A' then 10 
         when 'B' then 11 
         when 'C' then 12 
         when 'D' then 13 
         when 'E' then 14 
         when 'F' then 15 
  else 
         substr(pointer,1,1) 
  end)*16
    + 
  (case substr(pointer,2,1) 
         when 'A' then 10 
         when 'B' then 11 
         when 'C' then 12 
         when 'D' then 13 
         when 'E' then 14 
         when 'F' then 15 
  else 
         substr(pointer,2,1) 
  end)
  ),
  substr(pointer,3)
FROM 
  hexd 
WHERE 
  length(pointer)>0
)
 
SELECT
string AS ASCII_value,
'Registry.07.0' AS query
FROM hexd 
WHERE string != ''
ORDER BY pointer LIMIT 1