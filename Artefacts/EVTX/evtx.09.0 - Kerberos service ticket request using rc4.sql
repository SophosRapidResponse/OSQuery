/******************************* Sophos.com/RapidResponse *******************************\
| DESCRIPTION                                                                            |
| Detects potential Kerberos Service Ticket Requests related to a Golden Ticket attack.  |
| Requests using RC4 encryption (legacy) could indicate the second stage of the Golden   |
| Ticket attack in which an attacker holding the NTLM password hash of the KRBTGT account|
| could forge a Kerberos Ticket Granting Tickets (TGT). TACTIC: Credential Access        |
|                                                                                        |
| IMPORTANT                                                                              |
| If TA doesn't leverage the NTLM password hash but instead uses the newest encryption   |
| type for generating the golden ticket this detection will be evaded                    |
|                                                                                        |
| REFERENCE                                                                              |
| https://attack.mitre.org/techniques/T1558/001/                                         |
| https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769|
|                                                                                        |
| Author: The Rapid Response Team                                                        |
| github.com/SophosRapidResponse                                                         |
\****************************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS date_time,
    source,
    eventid,
    JSON_EXTRACT(data, '$.EventData.TargetUserName') AS Targeted_Username,
    JSON_EXTRACT(data, '$.EventData.TargetDomainName') AS Targeted_Domain,
    JSON_EXTRACT(data, '$.EventData.ServiceName') AS Service_Name,
    JSON_EXTRACT(data, '$.EventData.ServiceSid') AS Service_Sid,
    JSON_EXTRACT(data, '$.EventData.TicketOptions') AS Ticket_Option,
    JSON_EXTRACT(data, '$.EventData.TicketEncryptionType') AS Ticket_Encryption,
    JSON_EXTRACT(data, '$.EventData.IpAddress') || CHAR(58) || JSON_EXTRACT(data, '$.EventData.IpPort')  AS IP_port,
    'EVTX' AS data_source,
    'EVTX.09.0' AS query
FROM sophos_windows_events
WHERE
    source = 'Security' 
    AND eventid IN (4769, 4768)
    AND Service_Name LIKE '%$'
    AND Ticket_Option IN ('0x40810000','0x40800000','0x40810010') 
    AND Ticket_Encryption IN ('0x17','0x18')