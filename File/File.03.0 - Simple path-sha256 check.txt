/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This is a very simple query that only takes one path and returns files on disk |
| with their pathname and sha256. Minimal data to avoid any performance caps.    |
|                                                                                |
| VARIABLES                                                                      |
| path(file path) - file path                                                    |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
f.path AS Path,
h.sha256 AS SHA256,
'File/Hash' AS Data_Source,
'File.03.0' AS Query
FROM file f 
JOIN hash h ON f.path = h.path
WHERE f.path LIKE '$$path$$' AND f.filename != '.'