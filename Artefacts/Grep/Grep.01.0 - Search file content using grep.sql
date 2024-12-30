/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Uses grep to search for specific patterns or content within a file. Based on a |
| provided pattern, it returns matching lines from a specified file. If a pattern|
| isn't specified (%), it returns all lines from the file.                       |                                                              |
|                                                                                |
| EXAMPLE                                                                        |
| patten = 'hello'                                                               |
| path = 'C:\hello_world.txt'                                                    |
| file content:                                                                  |
|   hi my name is Sophos                                                         |
|   hello Sophos isn't OSQuery great                                             |
|   yes it is.                                                                   |
| returned data:                                                                 |
|   'hello Sophos isn't OSQuery great'                                           |
|                                                                                |
| VARIABLES                                                                      |
| path(filepath) - Needs to be the exact file path and filename, no wildcards    |
| pattern(string) - string pattern to match on, this is CASE SENSITIVE           |
|                                                                                |
| TIP                                                                            |
| As Grep only returns rows it finds a match on, you need to be careful to not   |
| incorrectly assume you have brought back the entire file.                      |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
    path, 
    pattern, 
    line,
    'Grep' AS Data_Source,
    'Grep.01.0' AS Query
FROM grep
WHERE pattern IN
    (CASE 
        WHEN '$$pattern$$' = '%' THEN ' ' 
        ELSE '$$pattern$$' 
     END)
    AND path = '$$path$$';