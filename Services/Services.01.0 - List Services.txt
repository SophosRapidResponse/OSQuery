/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List Windows Services and their properties.                                    |
|                                                                                |
| VARIABLES                                                                      |
| string_type(string) - name, display_name, status, start_type, path,            |
|                       module_path, description, user_account                   |
| value(string) - string to search for                                           |
|                                                                                |
| TIP                                                                            |
| If you want to bring back everything use 'name' for string_type and % for the  |
| value.                                                                         |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
name AS Name,
display_name AS Display_Name,
status AS Status,
start_type AS Start_Type,
path AS Path,
module_path AS Module_Path,
description AS Description,
user_account AS User_Account,
'Services' AS Data_Source,
'Services.01.0' AS Query
FROM services
WHERE $$string_type$$ LIKE '$$value$$'