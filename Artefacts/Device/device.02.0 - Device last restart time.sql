/**************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                     |
| Checks system uptime by identifying how long it has been since the last restart.|
|                                                                                 |
| Version: 1.0                                                                    |
| Author: @AltShiftPrtScn                                                         |
| github.com/SophosRapidResponse                                                  |
\*********************************************************************************/

SELECT 
days, 
hours, 
minutes, 
seconds,
'Uptime' AS Data_Source,
'Device.02.0' AS Query
FROM uptime