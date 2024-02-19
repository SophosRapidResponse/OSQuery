/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| The query look at Backgroud Activities Moderator (BAM) which tracks application|
| execution. Provides full path of executable that was run and last execution    |
| date/time                                                                      |
|                                                                                |
| VARIABLES:                                                                     |
| IOC                                                                            |
|                                                                                |
| TIP                                                                            |
| For the variable you can enter a filename, part of a path, username or SID.    |
| If you want to bring back everything use %                                     |
|                                                                                |
| LIMITATION                                                                     |
| BAM is a Windows service that Controls activity of background applications.    |
| This service exists in Windows 10 only.                                        |
|                                                                                |
| Version: 1.0                                                                   |
| Author: RAPID RESPONSE TEAM                                                    |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
REGEX_MATCH(bam.path, "[^\\]*$", 0) AS Name,
bam.path As Path, 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(bam.last_execution_time,'unixepoch')) AS Last_Execution_Time, 
h.sha256 As SHA256,
u.username As User,
bam.sid As User_Sid,
'background_activities_moderator' AS Data_Source,
'BackgroundActivityModerator.01.0' AS Query
FROM background_activities_moderator bam
JOIN users u ON bam.sid = u.uuid
JOIN hash h ON REPLACE(bam.path,regex_match(bam.path,'(\\Device\\HarddiskVolume.\\)',0),'C:\') = h.path
WHERE Name LIKE '%$$IOC$$%' OR User LIKE '%$$IOC$$' OR bam.sid = '$$IOC$$' OR REPLACE(bam.path,regex_match(bam.path,'(\\Device\\HarddiskVolume.\\)',0),'C:\') LIKE '%$$IOC$$%'