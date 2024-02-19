/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all browser extensions, web apps and add-ons installed on host. The query|
| covers Firefox Browser, Chromium-based browsers, and Internet Explorer.        |
|                                                                                |
| VARIABLE                                                                       |
| - user (type: STRING)                                                          |
| - extension (type: STRING)                                                     |
|                                                                                |
| The variable "user" allows searches for specific usernames.                    |
| The variable "extension" allow searches for extension name or ID               |
| The wildcard (%) can be used to get all data                                   |
|                                                                                |
| Version: 1.1                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

With browsers AS (
SELECT DISTINCT
    'Firefox' AS browser,
    firefox_addons.name,
    users.username,
    firefox_addons.identifier,
    firefox_addons.type,
    firefox_addons.version,
    firefox_addons.description,
    firefox_addons.path,
    '-' AS install_timestamp,
    '-' AS registry_path,
    '-' AS update_url,
    firefox_addons.location,
    firefox_addons.source_url,
    firefox_addons.visible,
    firefox_addons.active,
    firefox_addons.disabled,
    firefox_addons.autoupdate
FROM users
LEFT JOIN firefox_addons
    USING (uid)
WHERE firefox_addons.name IS NOT NULL

UNION 

SELECT DISTINCT
    'Chrome Extension' AS browser,
    chrome_extensions.name,
    users.username,
    chrome_extensions.identifier,
    '-' AS type,
    chrome_extensions.version,
    chrome_extensions.description,
    chrome_extensions.path,
    chrome_extensions.install_timestamp,
    '-' AS registry_path,
    chrome_extensions.update_url,
    '-' AS location,
    '-' AS source_url,
    '-' AS visible,
    '-' AS active,
    '-' AS disabled,
    '-' AS autoupdate
FROM users
LEFT JOIN chrome_extensions
    USING (uid)
WHERE chrome_extensions.name IS NOT NULL

UNION 

SELECT DISTINCT
    'Internet Explorer' AS browser,
    ie_extensions.name,
    '-' AS username,
    '-' AS identifier,
    '-' AS type,
    ie_extensions.version,
    '-' AS description,
    ie_extensions.path,
    '-' AS install_timestamp,
    ie_extensions.registry_path,
    '-' AS update_url,
    '-' AS location,
    '-' AS source_url,
    '-' AS visible,
    '-' AS active,
    '-' AS disabled,
    '-' AS autoupdate
FROM ie_extensions
WHERE ie_extensions.path != ''
)

SELECT 
    browser,
    name, 
    username,
    identifier,
    type,
    version,
    description,
    path,
    DATETIME(install_timestamp, 'unixepoch') AS install_time,
    registry_path,
    update_url,
    location,
    source_url,
    visible,
    active,
    disabled,
    autoupdate,
    'browser.02.0' AS query
FROM browsers
WHERE username LIKE '$$user$$' AND (name LIKE '$$extension$$' OR identifier LIKE '$$extension$$')