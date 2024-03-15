/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Looks for EID 4740 events generated on domain controllers, Windows servers, and|
| endpoint computers when user is locked out of an account.                      |
|                                                                                |
| VARIABLES                                                                      |
| username(string) - Account that was locked                                     |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time, 
eventid,  
JSON_EXTRACT(data, '$.EventData.TargetUserName') AS Target_Username,  
JSON_EXTRACT(data, '$.EventData.TargetDomainName') AS Target_DomainName,  
JSON_EXTRACT(data, '$.EventData.TargetSid') AS Target_SID,  
JSON_EXTRACT(data, '$.EventData.SubjectUserName') AS Source_Username,  
JSON_EXTRACT(data, '$.EventData.SubjectDomainName') AS Subject_DomainName,  
JSON_EXTRACT(data, '$.EventData.SubjectUserSid') AS Source_SID,  
'Security' AS Data_Source,
'Logins.06.0' AS Query 
FROM sophos_windows_events  
WHERE source = 'Security' 
	AND eventid = 4740
	AND JSON_EXTRACT(data, '$.EventData.TargetUserName') LIKE '$$username$$'
	AND time > 0