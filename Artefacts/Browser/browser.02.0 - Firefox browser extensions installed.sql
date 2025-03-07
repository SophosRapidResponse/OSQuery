/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Lists all Firefox extensions and add-ons installed on the host.                |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT 
firefox_addons.name,
firefox_addons.type,
users.username,
users.uuid,
users.uid,
firefox_addons.identifier,
firefox_addons.version,
firefox_addons.description,
firefox_addons.path,
firefox_addons.location,
firefox_addons.source_url,
firefox_addons.visible,
firefox_addons.active,
firefox_addons.disabled,
firefox_addons.autoupdate,
'browser.02.0' AS query
FROM users
LEFT JOIN firefox_addons
    USING (uid)
WHERE firefox_addons.name IS NOT NULL