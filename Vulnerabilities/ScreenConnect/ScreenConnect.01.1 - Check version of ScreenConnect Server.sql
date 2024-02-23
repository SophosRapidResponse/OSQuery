/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identifies machines running ScreenConnect Server vulnerable to Authentication  |
| Bypass (CVE-2024-1709 & CVE-2024-1708)                                         |
|                                                                                |
| Query Type: Data Lake                                                          |
| Author: The MDR team                                                           |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
    customer_id,
    meta_hostname,
    name,
    version,
    language,
    install_source,
    publisher,
    identifying_number,
    install_date,
    'datalake' AS data_source,
    'ScreenConnect.01.1' AS query
FROM
xdr_data
WHERE
  licence = 'MTR'
  AND query_name = 'windows_programs'
AND LOWER(name) = 'screenconnect'
and version < '23.9.8%'