/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look for suspicious services being installed via the System event log and      |
| Event ID 7045. This is a good query for finding Cobalt Strike services as      |
| PsExec and other suspicious services.                                          |
|                                                                                |
| SAFE IMAGE PATH                                                                |
| Some image paths contain malicious scripts or encoded PowerShell that once     |
| exported to Excel can get detected, if you want to keep a record of            |
| potentially malicious scripts you can use the 'Safe_Image_Path' value, this    |
| is still human readable and can be decoded with CyberChef here:                |
| https://tinyurl.com/2db7zxyk                                                   |
|                                                                                |
| Query Type: Endpoint                                                           |
| Author: @AltShiftPrtScn & Elida Leite                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH Path_List_info AS ( 
SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS date_time,
swe.eventid AS Event_ID,
JSON_EXTRACT(swe.data, '$.EventData.AccountName') AS Account_Name,
JSON_EXTRACT(swe.data, '$.EventData.ServiceName') AS Service_Name,
JSON_EXTRACT(swe.data, '$.EventData.ImagePath') AS Image_Path,
swe.user_id AS SID,
u.username AS Username,
u.directory AS Directory,
JSON_EXTRACT(swe.data, '$.EventData.ServiceType') AS Service_Type,
JSON_EXTRACT(swe.data, '$.EventData.StartType') AS Start_Type,
CASE
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%powershell%JAB%' THEN 'Low'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%H4s%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%powershell%invoke%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%-enc%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%-e %' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%-ec %' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%powershell%IEX%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%downloadstring%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%COMSPEC%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%Admin$%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%Psex%' THEN 'High'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%Paex%' THEN 'High'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%BTOBTO%' THEN 'Low'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%BTOBTO%' THEN 'Low'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%DllRegisterServer%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%.dll, DllRegisterServer%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%.dll Start%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%.dll AllocConsole%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%WinRing0x64.sys%' THEN 'High'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%AnyDesk%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%ProcessHacker%' THEN 'High'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%TeamViewer%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%AmmyyAdmin%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%vnc%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%LogMeIn%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') = 'AteraAgent' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%Splashtop%Remote Service%' THEN 'Medium'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%KrbSCM%' THEN 'High'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%krbrelay%' THEN 'High'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%echo%\pipe\%' THEN 'High'
	ELSE NULL
END AS 'Potential_FP_Chance',
CASE
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%powershell%JAB%' THEN 'When an b64 ecoded string starts with JAB or JABz it is highly likely to be Cobalt Strike. shorturl.at/mFZ68'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%H4s%' THEN 'When an b64 ecoded string starts with H4s it is highly likely to be Cobalt Strike. shorturl.at/mFZ68'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%powershell%invoke%' THEN 'PowerShell command to execute commands on local or remote computers. shorturl.at/mFZ68'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%-enc%' THEN 'PowerShell command to confirm a string is encoded.'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%-e %' THEN 'PowerShell command to confirm a string is encoded.'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%-ec %' THEN 'PowerShell command to confirm a string is encoded.'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%powershell%IEX%' THEN 'PowerShell command to execute commands on local or remote computers. shorturl.at/mFZ68'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%downloadstring%' THEN 'PowerShell command to download content from a remote URL/IP'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%COMSPEC%' THEN 'Command Specifier by default tells the computer to execute the command with CMD.exe'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%Admin$%' THEN 'Services with Admin$ in the path (C:\Windows) are often used by Cobalt Strike to deploy becons with random named EXEs'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%Psex%' THEN 'Relates to the use of PsExec, this has a high FP rate due to its legit use. Its presence does not by itself confirm suspicious activity.'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%Paex%' THEN 'Relates to the use of PaExec, this has a high FP rate due to its legit use. Its presence does not by itself confirm suspicious activity.'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%BTOBTO%' THEN 'Services with this name are typically connected to the use of SmbExec. shorturl.at/fxGHJ'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%BTOBTO%' THEN 'Services with this name are typically connected to the use of SmbExec. shorturl.at/fxGHJ'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%DllRegisterServer%' THEN 'Services with this in the image path do have a higher FP rate, but have also been seen used in Conti ransomware attacks'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%.dll, DllRegisterServer%' THEN 'Services with this in the image path do have a higher FP rate, but have also been seen used in Conti ransomware attacks'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%.dll Start%' THEN 'Services with this in the image path do have a higher FP rate, but have also been seen used in Conti ransomware attacks'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%.dll AllocConsole%' THEN 'Services with this in the image path do have a higher FP rate, but have also been seen used in Conti ransomware attacks'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%WinRing0x64.sys%' THEN 'XMRIG coinminer driver installation on the system' 
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%AnyDesk%' THEN 'Remote tool AnyDesk on the system' 
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%ProcessHacker%' THEN 'ProcessHacker tool on the system'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%TeamViewer%' THEN 'TeamViewer tool on the system'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%AmmyyAdmin%' THEN 'AmmyyAdmin tool on the system'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%vnc%' THEN 'vnc tool on the system'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%LogMeIn%' THEN 'LogMeIn tool on the system'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') = 'AteraAgent' THEN 'Atera tool on the system'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%Splashtop%Remote Service%' THEN 'Splashtop tool on the system'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ServiceName') LIKE '%KrbSCM%' THEN 'Default service name created by KrbRelayUp'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%krbrelay%' THEN 'Service associated with KrbRelayUp attack'
	WHEN JSON_EXTRACT(swe.data, '$.EventData.ImagePath') LIKE '%echo%\pipe\%' THEN 'GetSystem - used in Cobalt Beacon and Meterpreter'
ELSE NULL
END AS 'Description',
'System.evtx' AS Data_Source,
'Services.02.1' AS Query
FROM sophos_windows_events swe
LEFT JOIN users u ON swe.user_id = u.uuid
WHERE swe.source = 'System' 
AND swe.eventid = 7045
AND (
Image_Path LIKE '%powershell%JAB%' 
OR Image_Path LIKE '%SQB%' 
OR Image_Path LIKE '%H4s%' 
OR Image_Path LIKE '%powershell%invoke%' 
OR Image_Path LIKE '%-enc%' 
OR Image_Path LIKE '%-e %' 
OR Image_Path LIKE '%-ec %' 
OR Image_Path LIKE '%powershell%IEX%'
OR Image_Path LIKE '%downloadstring%' 
OR Image_Path like '%COMSPEC%' 
OR Image_Path like '%Admin$%' 
OR Image_Path like '%Psex%' 
OR Image_Path like '%Paex%' 
OR Image_Path like '%BTOBTO%' 
OR Image_Path like '%DllRegisterServer%' 
OR Image_Path like '%.dll, DllRegisterServer%' 
OR Image_Path like '%.dll, Start%' 
OR Image_Path like '%.dll AllocConsole%'
OR Image_Path LIKE '%WinRing0x64.sys%'
OR Service_Name LIKE '%AnyDesk%'
OR Service_Name LIKE '%ProcessHacker%'
OR Service_Name = 'BTOBTO'
OR Service_Name LIKE '%TeamViewer%'
OR Service_Name LIKE '%AmmyyAdmin%'
OR Service_Name LIKE '%vnc%'
OR Service_Name LIKE '%LogMeIn%'
OR Service_Name = 'AteraAgent'
OR Service_Name LIKE '%Splashtop%Remote Service%'
OR Service_Name LIKE '%KrbSCM%'
OR Image_Path LIKE '%krbrelay%'
OR Image_Path LIKE '%echo%\pipe\%'
)
AND swe.time > 0
)

SELECT
date_time,
Event_ID, 
Account_Name, 
Service_Name, 
Image_path,
SID, 
username, 
Directory, 
Service_Type, 
Start_Type, 
Potential_FP_Chance,
Description,
CAST ( (WITH RECURSIVE Counter(x) AS ( VALUES ( ( 1 ) ) UNION ALL SELECT x+1 FROM Counter WHERE x < length(Image_path) )
	SELECT GROUP_CONCAT(substr(Image_path, x, 1),CHAR(8729) ) FROM counter)
AS TEXT) Safe_Image_path,
Data_source,
Query
FROM Path_List_info
ORDER BY date_time DESC