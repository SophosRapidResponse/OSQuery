/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This query looks through the list of installed programs and event logs for     |
| evidence of legitimate remote access tools being installed.                    |
|                                                                                |
| REMOTE ACCESS TOOLS INCLUDED (commonly abused by threat actors)                |
| ScreenConnect                                                                  |
| TeamViewer                                                                     |
| Splashtop                                                                      |
| Atera                                                                          |
| Remote Utilities                                                               |
| AnyDesk                                                                        |
| TightVNC                                                                       |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
name AS Program_Name,
'' AS Service_Name,
CASE
   WHEN install_date != '' 
   THEN substr(Install_Date, 0, 5) || '-' || substr(Install_Date, 5, 2) || '-' || substr(Install_Date, 7, 2)
   END AS Install_Date,
'' AS Image_Path,
'' AS SID,
version AS Version,
install_location AS Install_Location,
install_source AS Install_Source,
publisher AS Publisher,
uninstall_string AS Uninstall_String,
'Programs' AS Data_Source,
'RMM-tools.01.0' AS Query
FROM programs
WHERE name LIKE 'ScreenConnect Client%'
OR name LIKE 'TeamViewer%'
OR name LIKE 'Splashtop%'
OR name LIKE 'AteraAgent%'
OR name LIKE 'Remote Utilities - Host%'
OR name LIKE 'AnyDesk%'
OR name LIKE 'TightVNC%'
OR name LIKE '%Ammyy%'
OR name LIKE '%Chrome Remote Desktop%'
OR name LIKE '%Dameware%'
OR name LIKE '%GoToAssist%'
OR name LIKE '%Intelliadmin%'
OR name LIKE '%Kaseya%'
OR name LIKE '%LogMeIn%'
OR name LIKE '%NetSupport%'
OR name LIKE '%Radmin%'
OR name LIKE '%Simple%help%'
OR name LIKE '%RemotePC%'
OR name LIKE '%RealVNC%'
OR name LIKE '%Remote Utilities%'
OR name LIKE '%SupRemo%'
OR name LIKE '%TigerVNC%'
OR name LIKE '%UltraViewer%'
OR name LIKE '%tacticalrmm%'
OR name LIKE '%meshcentral%'
OR name LIKE '%remotepc%'
OR name LIKE '%rustdesk%'
OR name LIKE '%action1%'

UNION ALL

SELECT
'' AS Program_Name,
JSON_EXTRACT(swe.data, '$.EventData.ServiceName') AS Service_Name,
strftime('%Y-%m-%dT%H:%M:%SZ',swe.datetime) AS Install_Date,
JSON_EXTRACT(swe.data, '$.EventData.ImagePath') AS Image_Path,
swe.user_id AS SID,
'' AS Version,
'' AS Install_Location,
'' AS Install_Source,
'' AS Publisher,
'' AS Uninstall_String,
'System Events' AS Data_Source,
'RMM-tools.01.0' AS Query  
FROM sophos_windows_events swe
JOIN users u ON swe.user_id = u.uuid
WHERE swe.source = 'System' 
AND swe.eventid = 7045
AND ((Service_Name LIKE 'AteraAgent%'
OR Service_Name LIKE 'ScreenConnect Client%'
OR Service_Name LIKE 'Splashtop%'
OR Service_Name LIKE 'TightVNC%'
OR Service_Name LIKE 'AnyDesk%'
OR Service_Name LIKE 'TeamViewer%'
OR Service_Name LIKE '%MeshCentral%'
OR Service_Name LIKE 'Remote Utilities - Host%')
OR (Image_Path LIKE '%AteraAgent.exe%'
OR Image_Path LIKE '%tvnserver.exe%'
OR Image_Path LIKE '%AnyDesk.exe%'
OR Image_Path LIKE '%TeamViewer_Service.exe'
OR Image_Path LIKE '%rutserv.exe%'
OR Image_Path LIKE '%ScreenConnect.ClientService.exe%'))
AND swe.time > 0
