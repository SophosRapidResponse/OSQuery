/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List logical drives and shared folders.                                        |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
device_id AS Path,
description AS Description,
'-' AS Name,
'Logical Drives' AS Data_Source,
'Device.03.0' AS Query
FROM logical_drives

UNION ALL

SELECT
path AS Path,
description AS Description,
name AS Name,
'Logical Drives' AS Data_Source,
'Device.03.0' AS Query    
FROM shared_resources