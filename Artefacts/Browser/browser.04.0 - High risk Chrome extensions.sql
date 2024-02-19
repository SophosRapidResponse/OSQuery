/*********************************** Sophos.com/RapidResponse ************************************\
| DESCRIPTION                                                                                     |
| Looks for extensions with high privileges or with scripts that can run on a website. The        |
| reference section links to a list of all permissions that generate warnings in Chrome. Focus on |
| those permissions and on those that connect to suspicious domains.                              |
|                                                                                                 |
| REFERENCE:                                                                                      |
| https://developer.chrome.com/docs/extensions/mv3/permission_warnings/#permissions_with_warnings |
|                                                                                                 |
| Version: 1.0                                                                                    |
| Author: The rapid response team |  Elida Leite                                                  |
| github.com/SophosRapidResponse                                                                  |
\*************************************************************************************************/

SELECT 
u.username, 
extensions.name, 
extensions.identifier, 
extensions.version, 
extensions.permissions, 
regex_match(extensions.permissions,'(www|http:|https:|\*:\/\/)+[^\s]+[\w]+[^\s]+[\w]',0) AS URL, 
extensions.optional_permissions, 
(SELECT 
chrome_extension_content_scripts.script FROM users 
JOIN chrome_extension_content_scripts USING (uid) 
) As script,
extensions.browser_type, 
extensions.path,
datetime(install_timestamp,'unixepoch') As Install_date,
 'browser.04.0' AS Query 
FROM users u 
JOIN chrome_extensions extensions USING (uid) 
WHERE extensions.permissions IS NOT NULL
AND (extensions.permissions LIKE 'clipboard%' 
    OR extensions.permissions LIKE '%tabs%' 
    OR extensions.permissions LIKE '*%://*/*%'
    OR extensions.permissions LIKE 'debugger'
    OR extensions.permissions LIKE 'desktopCapture'
    OR extensions.permissions LIKE 'history'
    OR extensions.permissions LIKE 'pageCapture'
    OR extensions.permissions LIKE 'proxy'
    OR extensions.permissions LIKE 'tabCapture'
    OR extensions.permissions LIKE 'webNavigation'
    OR extensions.permissions LIKE 'notifications')
AND extensions.identifier IS NOT 'pkedcjkdefgpdelpbcmbmeomcjbeemfm' --Chrome Media Router