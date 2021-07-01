/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check how long since the last reboot.                                          |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
CASE WHEN days <= 7 THEN 'Really good' 
     WHEN days >= 8 AND days <= 31 THEN 'Good'
     WHEN days >= 32 AND days <= 90 THEN 'Not great'
     WHEN days >= 91 AND days <= 365 THEN 'Bad'
     WHEN days >= 366 THEN 'Really bad!'
END AS Status,
days, hours, minutes, seconds,
'Uptime' AS Data_Source,
'Device.02.0' AS Query
FROM uptime