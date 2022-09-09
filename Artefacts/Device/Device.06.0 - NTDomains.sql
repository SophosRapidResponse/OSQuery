/******************* Sophos.com/RapidResponse *******************\
| DESCRIPTION                                                    |
| Display basic NT domain information of a Windows machine.      |
|                                                                |
| Version: 1.0                                                   |
| Author: The Rapid Response Team                                |
| github.com/SophosRapidResponse                                 |
\****************************************************************/

SELECT
    name,
    client_site_name,
    dc_site_name,
    dns_forest_name,
    domain_controller_address,
    domain_controller_name,
    domain_name,
    status,
    'ntdomains' AS Source,
    'NTDomains' AS Query
FROM ntdomains
WHERE domain_controller_name != ''