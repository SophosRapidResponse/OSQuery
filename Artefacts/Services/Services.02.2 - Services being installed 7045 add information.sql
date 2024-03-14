/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Retrieves all service installation events associated with EID 7045 from the    |
| Windows System event logs within a specified time frame. The query provides    |
| additional details such as file hashes, certificate information, and filesystem|
| timestamps.                                                                    |
|                                                                                |
| VARIABLE                                                                       |
| start_time (type: DATE)                                                        |
| end_time (type: DATE)                                                          |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team | Elida Leite                                  |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH windows_events AS (
SELECT
time,
datetime,
eventid,
source,
provider_name,
REPLACE(JSON_EXTRACT(data, '$.EventData.ImagePath'), '"', '') AS path_formatted,
user_id,
data
FROM
sophos_windows_events
WHERE eventid = 7045
AND source = 'System'
AND time >= $$start_time$$ 
AND time <= $$end_time$$
)

SELECT DISTINCT
strftime('%Y-%m-%dT%H:%M:%SZ',we.datetime) AS date_time,
we.eventid,
JSON_EXTRACT(we.data, '$.EventData.AccountName') AS account_name,
JSON_EXTRACT(we.data, '$.EventData.ServiceName') AS service_name,
JSON_EXTRACT(we.data, '$.EventData.ImagePath') AS image_path,
we.path_formatted,
JSON_EXTRACT(we.data, '$.EventData.ServiceType') AS service_type,
JSON_EXTRACT(we.data, '$.EventData.StartType') AS start_type,
u.uuid,
u.username,
h.sha256 AS sha256,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(file.btime,'unixepoch')) AS creation_time,
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(file.mtime,'unixepoch')) AS modified_time,
JSON_EXTRACT(sfp.local_rep_data, '$.reputationData.details.CompanyName') AS company_name,
JSON_EXTRACT(sfp.local_rep_data, '$.reputationData.details.FileDescription') AS file_description,
JSON_EXTRACT(sfp.local_rep_data, '$.reputationData.details.FileVersion') AS file_version,
JSON_EXTRACT(sfp.local_rep_data, '$.reputationData.details.OriginalFilename') AS original_filename,
JSON_EXTRACT(sfp.local_rep_data, '$.reputationData.isSigned') AS is_signed,
JSON_EXTRACT(sfp.local_rep_data, '$.reputationData.signerInfo[0].isValid') AS is_valid,
JSON_EXTRACT(sfp.local_rep_data, '$.reputationData.signerInfo[0].signer') AS signer,
JSON_EXTRACT(sfp.local_rep_data, '$.reputationData.signerInfo[0].thumbprint') AS signer_thumbprint,
we.source,
we.provider_name,
'EVTX' AS data_source,
'Service.02.2' AS query
FROM windows_events AS we
LEFT JOIN hash AS h ON
    h.path LIKE LOWER(path_formatted)
LEFT JOIN sophos_file_properties AS sfp ON
    sfp.path = LOWER(path_formatted)
LEFT JOIN file ON 
   file.path LIKE LOWER(path_formatted)
LEFT JOIN users u 
    ON we.user_id = u.uuid