/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Hunts for a possible theft of the NTDS database. Looks for the EID 325 in the  |
| Application logs for new database created. TACTIC: Credential Access           |
|                                                                                |
| There are other event IDs of interest in ESENT that can provide additional     |
| information, such as EID: 216, 326, 327. However, due to the high amount of FP |
| generated by them this query focus on the Event ID 325 (new database created)  |
|                                                                                |
| REFERENCE:                                                                     |
| - https://attack.mitre.org/techniques/T1003/003/                               |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author:  Robert Weiland                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
source,
provider_name,
regex_split(data,',',6) AS New_Database_Path,
REPLACE(regex_match(data,'C:[^,]+[.]\w{1,3}',0),'\\','\') AS New_Database_Path_2, --(parse the whole data field to match the pattern of filepath starting with C:)
data AS raw_data,
'EVTX' AS data_source,
'EVTX.05.0' AS query 
FROM sophos_windows_events
WHERE source = 'Application' 
AND Provider_Name = 'ESENT' 
AND eventid = 325 
AND data like '%ntds.dit%'
AND time > 0