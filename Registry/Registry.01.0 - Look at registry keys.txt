/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look at registry keys by path.                                                 |
|                                                                                |
| VARIABLE                                                                       |
| path(string) = registry key path                                               |
|                                                                                |
| EXAMPLE                                                                        |
| path = HKEY_USERS\%\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\%            |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
CAST(strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime,'unixepoch')) AS TEXT) Last_Modified,
path AS Path,
name AS Name,
type AS Type,
data AS Data,
'Registry' AS Data_Source,
'Registry.01.0' AS Query
FROM registry WHERE path LIKE '$$path$$' 