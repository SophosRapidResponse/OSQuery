/*********************************** Sophos.com/RapidResponse ***********************************\
| DESCRIPTION                                                                                     |
| The query aims to find extensions with high privileges and extensions with scripts that can run |
| on a website. In the reference section, there is a link to a list with all the permissions that |
| generate warnings in Chrome. The analyst should focus on permissions that generate warnings but |
| as well as pay attention to the ones that connect to shady domains.                             |
|                                                                                                 |
| REFERENCE:                                                                                      |
| https://developer.chrome.com/docs/extensions/mv3/permission_warnings/#permissions_with_warnings |
|                                                                                                 |
| Version: 1.0                                                                                    |
| Author: Elida Leite                                                                             |
| github.com/SophosRapidResponse                                                                  |
\*************************************************************************************************/

SELECT 
u.username, 
extensions.name, 
extensions.identifier, 
extensions.version, 
extensions.permissions, 
extensions.optional_permissions, 
(SELECT 
chrome_extension_content_scripts.script FROM users 
JOIN chrome_extension_content_scripts USING (uid) 
) As script,
extensions.browser_type, 
extensions.path,
datetime(install_timestamp,'unixepoch') As Install_date,
 'Medium' As Potential_FP_chance,
 'Users/chrome_extensions/chrome_extension_content_scripts' AS Data_Source,
 'T1176 - High Risk Chrome Extensions' AS Query 
FROM users u 
JOIN chrome_extensions extensions USING (uid) 
WHERE extensions.permissions IS NOT ''
AND (extensions.permissions LIKE '%' OR extensions.permissions LIKE '%tabs%' OR extensions.permissions LIKE '*%://*/*%')