/*************************** Sophos.com/RapidResponse ***************************\
|                                                                                |
| DESCRIPTION                                                                    |
| If a threat actor is using the legitimate remote access tool ScreenConnect to  |
| to tranfer files to the victims device, or execute files through               |
| ScreenConnect, these events are recorded in the Application Event log.         |
| Unfortunately only the filename and not the path is recorded. However, using   |
| the Sophos File Journal can reveal this.                                       |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime, 
provider_name AS Provider_name, 
data AS Data,
'Application Events' AS Data_Source,
'T1105 - Ingress Tool Transfer (files transfered_executed via ScreenConnect)' AS Query  
FROM sophos_windows_events WHERE source = 'Application' and eventid = 0 and Provider_Name like 'ScreenConnect%' and data like '%Transferred files%'