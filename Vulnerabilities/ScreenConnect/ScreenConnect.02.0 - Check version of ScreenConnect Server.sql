/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identifies machines running ScreenConnect Server vulnerable to Authentication  |
| Bypass (CVE-2024-1709 & CVE-2024-1708)                                         |
|                                                                                |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT DISTINCT
   f.filename,
   f.path,
   f.product_version,
    'file' AS data_source,
    'ScreenConnect.02.' AS query
 FROM
   file AS f
 JOIN
   (SELECT REPLACE(path, '"', '') AS path FROM services WHERE name = 'ScreenConnect Web Server') AS s
 ON
   f.path = s.path
 WHERE
   (f.product_version < '23.9.8' OR f.product_version LIKE '23.9.7%');
