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
    '-' AS registry_path,
    '-' AS update_url,
    firefox_addons.location,
    firefox_addons.source_url,
    firefox_addons.visible,
    firefox_addons.active,
    firefox_addons.disabled,
    firefox_addons.autoupdate,
    firefox_addons.native,
    '-' AS local_rep,
    '-' AS global_rep,
    '-' AS ml_score,
    '-' AS pua_score
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
    '-' AS registry_path,
    chrome_extensions.update_url,
    '-' AS location,
    '-' AS source_url,
    '-' AS visible,
    '-' AS active,
    '-' AS disabled,
    '-' AS autoupdate, 
    '-' AS native,
    '-' AS local_rep,
    '-' AS global_rep,
    '-' AS ml_score,
    '-' AS pua_score
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
    ie_extensions.registry_path,
    '-' AS update_url,
    '-' AS location,
    '-' AS source_url,
    '-' AS visible,
    '-' AS active,
    '-' AS disabled,
    '-' AS autoupdate, 
    '-' AS native,
    sophos_file_properties.local_rep,
    sophos_file_properties.global_rep,
    sophos_file_properties.ml_score,
    sophos_file_properties.pua_score
FROM ie_extensions
LEFT JOIN sophos_file_properties
    ON ie_extensions.path = sophos_file_properties.path
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
    registry_path,
    update_url,
    location,
    source_url,
    visible,
    active,
    disabled,
    autoupdate, 
    native,
    local_rep,
    global_rep,
    ml_score,
    pua_score
FROM browsers
WHERE username LIKE '$$user$$' AND (name LIKE '$$extension$$' OR identifier LIKE '$$extension$$')