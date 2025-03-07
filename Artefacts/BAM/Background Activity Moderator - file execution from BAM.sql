/*************************** Sophos.com/RapidResponse ****************************\
| DESCRIPTION                                                                     |
| The Background Activity Moderator (BAM) is a Windows service responsible for    |
| managing the activity of background applications. It records the full path of   |
| the executable file that was run on the system and the last date and time it was|
| run.                                                                            |
|                                                                                 |
| VARIABLE:                                                                       |
| - username (type: STRING)                                                       |
| - user_sid (type: STRING)                                                       |
| - file_path (type: STRING)                                                      |
| TIP                                                                             |
| For the variable you can enter a filename, part of a path, username or SID.     |
| If you want to bring back everything use %                                      |
|                                                                                 |
| LIMITATION                                                                      |
| BAM is a Windows service that Controls activity of background applications.     |
| This service exists in Windows 10 only.                                         |
|                                                                                 |
| Version: 1.0                                                                    |
| Author: RAPID RESPONSE TEAM                                                     |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/

SELECT 
REGEX_MATCH(bam.path, "[^\\]*$", 0) AS name,
bam.path, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(bam.last_execution_time,'unixepoch')) AS Last_Execution_Time, 
hash.sha256,
u.username,
bam.sid,
'Background Activity Moderator' AS Query
FROM background_activities_moderator AS bam
JOIN users u ON bam.sid = u.uuid
LEFT JOIN hash ON REPLACE(bam.path,regex_match(bam.path,'(\\Device\\HarddiskVolume.\\)',0),'C:\') = hash.path
WHERE 
u.username LIKE '$$username$$' 
AND bam.sid LIKE '$$user_sid$$' 
AND REPLACE(bam.path,regex_match(bam.path,'(\\Device\\HarddiskVolume.\\)',0),'C:\') LIKE '%$$file_path$$%'
ORDER BY bam.last_execution_time DESC