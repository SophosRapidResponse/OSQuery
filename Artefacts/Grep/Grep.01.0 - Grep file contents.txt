/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The GREP table allows you to search file content for matching string patterns. |
| Any pattern it matches it will return the whole row of text that pattern was   |
| matched on.                                                                    |
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
| incorrectly assume you have brought back the entire file. If you are trying to |
| bring back every row, then normally a space charector for the pattern works    |
| best, however you use can't use a space as a variable, so use the word 'space' | 
| instead i.e. pattern = 'space' (lowercase).                                    |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT path, pattern, line,
'Grep' AS Data_Source,
'Grep.01.0' AS Query
FROM grep
WHERE pattern IN ( SELECT CASE  WHEN '$$pattern$$' = 'space' THEN ' ' ELSE '$$pattern$$'  END) 
   AND path = '$$path$$'