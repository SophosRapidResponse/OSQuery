/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| Check the User.xml file found in the ScreenConnect\App_Data folder for possible |
| signs of exploitation in the ScreenConnect Server. The content of the file will |
| be updated when an attacker executes the exploit and creates a new user.        |
|                                                                                 |
| Details in the XML include the new user created, email address and details for  |
| the password change.                                                            |
|                                                                                 |
| Query Type: Endpoint                                                            |
| Author: The Rapid Response Team  | Lee Kirkpatrick                              |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/

SELECT 
grep.path, 
grep.line,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(file.mtime,'unixepoch')) AS 'last_modified_time', 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(file.btime,'unixepoch')) AS 'created_time',
'file' AS data_source,
'ScreenConnect.03.' AS query
FROM file 
CROSS JOIN grep ON (grep.path = file.path) 
WHERE 
file.path LIKE 'C:\Program Files (x86)\ScreenConnect\App_Data\User.xml' 
AND grep.pattern = ' ' 