/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Use the Shodan API to get information the public IP of each device		 |
|                                                                                |
| Query Type: Endpoint                                                           |
| Author: @mvaldivieso                                 				 |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/
WITH public_ip AS (
    SELECT SUBSTR(result, 1, LENGTH(result) - 1) AS ip FROM curl WHERE url='
https://ipv4.icanhazip.com'
),
shodan_response AS (
    SELECT result AS shodan_result 
    FROM curl WHERE url=CONCAT('
https://api.shodan.io/shodan/host/'
, (SELECT ip FROM public_ip), '?key=$$shodan_key$$')
)
SELECT 
   (SELECT ip from public_ip) as IP,
    JSON_EXTRACT((SELECT shodan_result FROM shodan_response), '$.city') AS City,
    JSON_EXTRACT((SELECT shodan_result FROM shodan_response), '$.country_name') AS Country,
    JSON_EXTRACT((SELECT shodan_result FROM shodan_response), '$.os') AS OS,
    JSON_EXTRACT((SELECT shodan_result FROM shodan_response), '$.ports') AS Ports,
    JSON_EXTRACT((SELECT shodan_result FROM shodan_response), '$.hostnames') AS Hostnames,
    JSON_EXTRACT((SELECT shodan_result FROM shodan_response), '$.vulns') AS Vulnerabilities
FROM
    shodan_response;