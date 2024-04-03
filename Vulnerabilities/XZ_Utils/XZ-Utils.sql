/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Searches for Linux machines that contains the XZ Utils package and checks if   |
| they are running the vulnerable versions 5.6.0 or 5.6.1 associated with the    |
| CVE-2024-3094                                                                  |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
CASE
    WHEN p.source = 'DEB Package' THEN 'DEB Package'
    WHEN p.source = 'RPM Package' THEN 'RPM Package'
END AS source,
p.name,
p.version,
CASE
    WHEN p.version = '5.6.0' OR p.version = '5.6.1' THEN 'Vulnerable'
    ELSE 'Not vulnerable'
END AS status
FROM (
    SELECT 'DEB Package' AS source, name, version
    FROM deb_packages
    UNION ALL
    SELECT 'RPM Package' AS source, name, version
    FROM rpm_packages
) AS p
WHERE p.name = 'xz-utils' 
OR p.name = 'liblzma' 
OR p.name LIKE 'liblzma%'
