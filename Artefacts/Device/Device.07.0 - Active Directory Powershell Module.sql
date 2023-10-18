SELECT
name AS feature_name,
caption,
statename AS state,
'windows optional features' AS data_source,
'Device.07.0' AS query
FROM windows_optional_features
WHERE name = 'ActiveDirectory-PowerShell'
AND statename = 'Enabled'