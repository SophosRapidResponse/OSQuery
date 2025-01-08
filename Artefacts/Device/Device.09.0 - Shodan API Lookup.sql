/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This query uses the Shodan API to get information about public IP address      |
| associated with each device. Note that the returned public IP may correspond to|
| the internet gateway rather than the specific device itself.                   |
|                                                                                |
| VARIABLE                                                                       |
| - shodan_key (data type: String)                                               |
|                                                                                |
| Query Type: Endpoint                                                           |
| Author: @mvaldivieso                                                           |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH public_ip AS (
  SELECT SUBSTR(result, 1, LENGTH(result) - 1) AS ip 
  FROM curl 
  WHERE url='https://ipv4.icanhazip.com'
),
shodan_response AS (
  SELECT result
  FROM curl
  WHERE url=CONCAT('https://api.shodan.io/shodan/host/', (SELECT ip FROM public_ip), '?key=$$shodan_key$$')
)
SELECT 
(SELECT ip FROM public_ip) AS public_ip,
JSON_EXTRACT(sr.result, '$.city') AS City, 
JSON_EXTRACT(sr.result, '$.country_name') AS Country,
JSON_EXTRACT(sr.result, '$.os') AS OS,
JSON_EXTRACT(sr.result, '$.ports') AS Ports,
JSON_EXTRACT(sr.result, '$.hostnames') AS Hostnames,
JSON_EXTRACT(sr.result, '$.vulns') AS Vulnerabilities,
'curl' AS source,
'Device.09.0' AS query
FROM shodan_response AS sr