/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets user shellbags information. This is great for helping understand what a   |
| user accessed.                                                                 |
|                                                                                |
| VARIABLE                                                                       |
| sid(string) = SID of the user                                                  |
|                                                                                |
| TIP                                                                            |
| If you want to bring back everything use % for sid.                            |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
sb.path,
sb.sid,
u.username, 
strftime('%Y-%m-%dT%H:%M:%SZ', sb.created_time,'unixepoch') AS Created_Time, 
strftime('%Y-%m-%dT%H:%M:%SZ', sb.modified_time,'unixepoch') AS Last_Modified, 
strftime('%Y-%m-%dT%H:%M:%SZ', sb.accessed_time,'unixepoch') AS Last_Accessed, 
'Shellbags' AS Data_Source,
'Shellbags.01.0' AS Query
FROM shellbags sb
JOIN users u ON sb.sid = u.uuid
WHERE sb.sid LIKE '$$sid$$'