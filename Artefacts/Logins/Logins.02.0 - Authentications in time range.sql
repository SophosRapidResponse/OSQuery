/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets all successful and failed logins (event IDs 4624 and 4625) from the       |
| 'sophos_winsec_journal' table.                                                 |
|                                                                                |
| VARIABLES                                                                      |
| - username (type: Username)                                                    |
| - source_ip (type: IP address)                                                 |
| - logon_type (type: string)                                                    |
| - start_time (type: date)                                                      |
| - end_time (type: date)                                                        |
|                                                                                |
| TIP                                                                            |
| Use wildcards for username, source_ip, and logon_type if you want all data to  |
| be returned                                                                    |
|                                                                                |
| Version: 1.3                                                                   |
| Author: the Rapid Response Team / @AltShiftPrtScn                              |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
strftime('%Y-%m-%dT%H:%M:%SZ', datetime(time,'unixepoch')) AS date_time,
CAST(JSON_EXTRACT(data, '$.authenticationPackageName') AS TEXT) AS auth_package_name,
CAST(JSON_EXTRACT(data, '$.targetDomainName') AS TEXT) domain_name,
CAST(JSON_EXTRACT(data, '$.targetUserName') AS TEXT) AS username,
CAST(JSON_EXTRACT(data, '$.ipAddress') AS TEXT) AS remote_address,
CASE JSON_EXTRACT(data, '$.logonType')
    WHEN 2 THEN 'Logon Type 2 - Interactive'
    WHEN 3 THEN 'Logon Type 3 - Network'
    WHEN 4 THEN 'Logon Type 4 - Batch'
    WHEN 5 THEN 'Logon Type 5 - Service'
    WHEN 6 THEN 'Logon Type 6 - Proxy'
    WHEN 7 THEN 'Logon Type 7 - Unlock'
    WHEN 8 THEN 'Logon Type 8 - NetworkCleartext'
    WHEN 9 THEN 'Logon Type 9 - NewCredentials'
    WHEN 10 THEN 'Logon Type 10 - RemoteInteractive'
    WHEN 11 THEN 'Logon Type 11 - CachedInteractive'
    WHEN 12 THEN 'Logon Type 12 - Cached Remote Interactive'
    ELSE 'UNKNOWN TYPE: ' || JSON_EXTRACT(data,'$.EventData.LogonType')
END AS logon_type,
event_type AS event_id,
CASE event_type
    WHEN 4624 THEN 'Authenticated'
    ELSE CASE JSON_EXTRACT(data, '$.subStatus')
            WHEN '0xc000005e' THEN 'There are currently no logon servers available to service the logon request'
            WHEN '0xc0000064' THEN 'Incorrect User - User logon with misspelled or bad user account'
            WHEN '0xc000006a' THEN 'Incorrect Password - User logon with misspelled or bad password'
            WHEN '0xc000006d' THEN 'Incorrect User or Auth - This is either due to a bad username or authentication information'
            WHEN '0xc000006f' THEN 'User logon outside authorized hours'
            WHEN '0xc0000070' THEN 'User logon from unauthorized workstation'
            WHEN '0xc0000072' THEN 'Disabled - User logon to account disabled by administrator'
            WHEN '0xc000015b' THEN 'The user has not been granted the requested logon type (aka logon right) at this machine'
            WHEN '0xc0000192' THEN 'An attempt was made to logon, but the Netlogon service was not started'
            WHEN '0xc0000193' THEN 'Expired - User logon with expired account'
            WHEN '0xc0000413' THEN 'Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine'
            ELSE 'UNKNOWN: ' || JSON_EXTRACT(data, '$.subStatus')
        END
END result,
CAST(JSON_EXTRACT(data, '$.processName') AS TEXT) AS process_name,
'Winsec Journal' AS data_source,
'Logins.02.0' AS query
FROM sophos_winsec_journal
WHERE event_type IN ('4624','4625')
    AND IFNULL(JSON_EXTRACT(data, '$.targetUserName'), '') LIKE '$$username$$'
    AND IFNULL(JSON_EXTRACT(data, '$.ipAddress'), '') LIKE '$$source_ip$$'
    AND IFNULL(JSON_EXTRACT(data, '$.logonType'), '') LIKE '$$logon_type$$'
    AND time >= CAST($$start_time$$ AS INT)
    AND time <= CAST($$end_time$$ AS INT)