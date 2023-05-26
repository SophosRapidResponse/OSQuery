/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Look for services being installed via the System event log and Event ID 7045   |
| for a specific time frame. Gets additional information such as hashes, cert    |
| information, and file timestamps                                               |
|                                                                                |
| VARIABLE                                                                       |
| start_time (type: DATE)                                                        |
| end_time (type: DATE)                                                          |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH windows_events AS (
SELECT
time,
datetime,
eventid,
source,
provider_name,
user_id,
data,
EXPAND_ENV(REPLACE(REPLACE(JSON_EXTRACT(data, '$.EventData.ImagePath'), '"', ''), '\SystemRoot', '%SystemRoot%')) AS path_formatted
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
'Services being installed 7045 with add information' AS query
FROM windows_events AS we
LEFT JOIN hash AS h ON
    h.path LIKE LOWER(we.path_formatted)
LEFT JOIN sophos_file_properties AS sfp ON
    sfp.path = LOWER(we.path_formatted)
LEFT JOIN file 
    ON LOWER(we.path_formatted) = file.path
LEFT JOIN users u 
    ON we.user_id = u.uuid
