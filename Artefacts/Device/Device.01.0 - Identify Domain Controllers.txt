/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This will check the registry for the 'LanmanNT' value in 'HKLM\System\         |
| CurrentControlSet\Control\ProductOptions\ProductType' key, if it exists it     |
| means that server is a domain controller.                                      |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
CASE WHEN data = 'LanmanNT' THEN 'Yes' ELSE 'No' END AS 'Is_Domain_Controller?',
'Registry' AS Data_Source,
'Device.01.0' AS Query
FROM registry WHERE path = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType' AND data = 'LanmanNT'