/*************************** Sophos.com/RapidResponse ***************************\
|                                                                                |
| DESCRIPTION                                                                    |
| Looking for suspicious HealthMailbox logins. Legit UPNs should have            |
| "HealthMailbox+32characterString" where most malicious ones have +7 stirngs.   |
|                                                                                |
| Version: 1.0                                                                   |
| Author: @AltShiftPrtScn                                                        |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
STRFTIME('%Y-%m-%dT%H:%M:%SZ', DATETIME(logon_time, 'unixepoch')) AS Logon_Time,
user AS User,
logon_sid AS SID,
upn AS UPN,
CASE 
WHEN LENGTH(SPLIT(upn,'@',0)) = 45 THEN 'Likely legit'
WHEN LENGTH(SPLIT(upn,'@',0)) < 45 THEN 'Suspicious'
END AS Mailbox,
'Logon Sessions' AS Data_Source,
'ProxyShell.05.0' AS Query
FROM logon_sessions
WHERE user LIKE 'HealthMailbox%'