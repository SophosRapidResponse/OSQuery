/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Collects all user details or searches for specific users.                      |
|                                                                                |
| VARIABLES                                                                      |
| username(username) = username to search for                                    |
| directory(file path) = Users directory                                         |
| description(string) = users description                                        |
| uuid(string) = users UUID/SID                                                  |
| type(string) = users type e.g. roaming, local                                  |
|                                                                                |
| TIP                                                                            |
| Use wildcards for each variable if you want to bring all users back.           |
|                                                                                |
| Version: 1.2                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
uuid AS 'UUID_SID',
username AS Username,
CASE
	WHEN description LIKE 'Built-in account for%' THEN type || ' - T1078.001'
	WHEN type = 'local' THEN type || ' - T1078.003'
	WHEN type = 'roaming' THEN type || ' - T1078.002'
	ELSE type
END AS Type,
description AS Description,
directory AS Directory,
'Users' AS Data_Source,
'User.01.0' AS Query
FROM users
WHERE username LIKE '$$username$$' AND directory LIKE '$$directory$$' AND description LIKE '$$description$$' AND uuid LIKE '$$uuid$$' AND type LIKE '$$type$$'