/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Check when the Sophos data lake started recording events. Outputs the date/time|
| for the first and last time events added to the data lake.                     |
|                                                                                |
| The query uses a variable for hostname in case need to filter per-device basis |
| A wildcard can be used to return data from all devices.                        |
|                                                                                |
| VARIABLES                                                                      |
| - hostname (type: Device Name)                                                 |
|                                                                                |
| Query Type: Data Lake                                                          |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH data AS (
SELECT
   meta_hostname,
   ingestion_timestamp AS date
FROM
   xdr_data
GROUP BY
   meta_hostname,
   ingestion_timestamp
ORDER BY date ASC
)

SELECT
meta_hostname, 
MIN(date) AS first_ingestion_time,
MAX(date) AS last_ingestion_time,
'xdr_data' AS data_source,
'Sophos.05.0' AS query
FROM data
WHERE meta_hostname LIKE '$$hostname$$'
GROUP BY meta_hostname
ORDER BY first_ingestion_time ASC