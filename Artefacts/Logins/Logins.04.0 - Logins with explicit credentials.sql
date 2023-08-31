/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look for login attempts using explicit credentials.                            |
|                                                                                |
| VARIABLES                                                                      |
| username(string) - username of the source or target account                    |
| target_computer(string) - computer they are logging into                       |
|                                                                                |
| TIP                                                                            |
| If you know a compromised account this can help identify what they were        |
| logging into, also good when you know a specific machine is being targetted.   |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS Datetime, 
swe.eventid AS Event_ID,  
JSON_EXTRACT(swe.data, '$.EventData.SubjectUserName') AS Source_Username,  
JSON_EXTRACT(swe.data, '$.EventData.SubjectUserSid') AS Source_SID,  
JSON_EXTRACT(swe.data, '$.EventData.TargetServerName') AS Target_Computer_Name,  
JSON_EXTRACT(swe.data, '$.EventData.TargetUserName') AS Target_Username,  
JSON_EXTRACT(swe.data, '$.EventData.ProcessName') AS ProcessName, 
'Security EVTX' AS Data_Source,
'Logins.04.0' AS Query 
FROM sophos_windows_events swe  
WHERE swe.source = 'Security' AND swe.eventid = 4648
AND (Source_Username LIKE '$$username$$' OR Target_Username LIKE '$$username$$') AND Target_Computer_Name LIKE '$$target_computer$$'

