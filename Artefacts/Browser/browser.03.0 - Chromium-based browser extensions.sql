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
    chrome_extensions.name AS extension_name,
    chrome_extensions.identifier AS extension_identified,
    chrome_extensions.version,
    chrome_extensions.description,
    chrome_extensions.path,
    users.username,
    users.uuid AS SID,
    users.uid,
    DATETIME( chrome_extensions.install_timestamp, 'unixepoch') AS install_time,
    chrome_extensions.update_url, 
    'browser.03.0' AS query
FROM users
LEFT JOIN chrome_extensions
    USING (uid)
WHERE chrome_extensions.name IS NOT NULL