/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Checks if Sophos Tamper Protection is turned off.                              |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
CASE data WHEN '0' THEN 'DISABLED' ELSE 'Enabled' END AS Tamper_Protection, 
path AS Path,
'Registry' AS Data_Source,
'Sophos.01.0' AS Query
FROM registry WHERE key ='HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Sophos Endpoint Defense\TamperProtection\Config' AND name = 'SEDEnabled' AND data = 0