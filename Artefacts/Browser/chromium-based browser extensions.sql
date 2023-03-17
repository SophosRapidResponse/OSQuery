/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all Chromium-based browser extensions installed on devices               |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
    chrome_extensions.browser_type,
    chrome_extensions.name,
    users.username,
    chrome_extensions.identifier,
    chrome_extensions.version,
    chrome_extensions.description,
    chrome_extensions.path,
    DATETIME( chrome_extensions.install_timestamp, 'unixepoch') AS install_time,
    chrome_extensions.update_url
FROM users
LEFT JOIN chrome_extensions
    USING (uid)
WHERE chrome_extensions.name IS NOT NULL