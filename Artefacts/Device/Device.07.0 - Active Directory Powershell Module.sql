/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all devices that have installed/enabled the Active Directory PowerShell   |
| module. The module is automatically installed on domain controllers, however,  |
| it can be installed on other devices to allow remote management of the Active  |
| Directory environment                                                          |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
name AS feature_name,
caption,
statename AS state,
'windows optional features' AS data_source,
'Device.07.0' AS query
FROM windows_optional_features
WHERE name = 'ActiveDirectory-PowerShell'
AND statename = 'Enabled'