/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all macOS applications installed in known search paths                    |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(last_opened_time, 'unixepoch')) AS last_opened,
    display_name,
    name,    
    path,
    bundle_name,
    bundle_executable,
    bundle_identifier,
    bundle_version,
    bundle_package_type,
    CASE WHEN element = 1 THEN 'True' ELSE 'False' END AS background_agent,
    development_region,
    category,
    copyright
FROM
  apps
ORDER BY last_opened_time DESC