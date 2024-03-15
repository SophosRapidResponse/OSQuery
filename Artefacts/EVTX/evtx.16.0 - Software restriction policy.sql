/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| List all blocking events generated by the Software Restriction Policy (SRP)    |
|                                                                                |
| REFERENCE                                                                      |
| https://learn.microsoft.com/en-us/windows-server/identity/software-restriction-|
| policies/software-restriction-policies                                         |
| https://www.isssource.com/wp-content/uploads/2012/02/ISSSource-Application_    |
| Whitelisting_Using_SRP.pdf                                                     |
|                                                                                |
| Query Type: Endpoint                                                           |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', MIN(datetime)) AS first_occurance,
    STRFTIME('%Y-%m-%dT%H:%M:%SZ', MAX(datetime)) AS last_occurance,
    COUNT(*)  AS instance,
    source,
    provider_name,
    eventid,
    CASE WHEN eventid = 865 THEN 'SRP - Blocked by default disallow rule'
    WHEN eventid = 866 THEN 'SRP - Blocked by path rule' 
    WHEN eventid = 867 THEN ' SRP - Blocked by publisher rule'
    WHEN eventid = 868 THEN 'SRP - Blocked by hash or zone rule'
    WHEN eventid = 882 THEN 'SRP - Blocked, but no UI acknowledgement shown' END AS details,
    CAST(JSON_EXTRACT(data, '$.UserData.AttemptedPath')AS TEXT) AS blocked_program, 
    CAST(JSON_EXTRACT(data, '$.UserData.RulePath')AS TEXT) AS rule_path,
    CAST(JSON_EXTRACT(data, '$.UserData.SrpRuleGuid') AS TEXT) AS rule_Guid,
    data AS raw,
    'EVTX' AS Data_Source,
    'EVTX - Software Restriction Policy' AS Query 
FROM sophos_windows_events 
WHERE source LIKE 'Application'
    AND provider_name = 'Microsoft-Windows-SoftwareRestrictionPolicies'
    AND eventid IN ('865','866','867','868','882')
    AND time > 0
GROUP BY blocked_program