/******************************* Sophos.com/RapidResponse *******************************\
| DESCRIPTION                                                                            |
| Detects potential Kerberos Service Ticket Request related to a Golden Ticket attack    |
| Requests using RC4 encryption (legacy) could indicate the second stage of the Golden   |
| ticket attack in which TA holding KRBTGT account NTLM password hash could forge a TGT. |
| EID (4768) was added in this query as well as per MITRE recommendation                 |
|                                                                                        |
| IMPORTANT                                                                              |
| If TA doesn't leverage the NTLM password hash but instead uses the newest encryption   |
| type for generating the golden ticket this detection will be evaded                    |
|                                                                                        |
| REFERENCE                                                                              |
| https://attack.mitre.org/techniques/T1558/001/                                         |
| https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769|
|                                                                                        |
| Author: Elida Leite                                                                    |
| github.com/SophosRapidResponse                                                         |
\****************************************************************************************/

SELECT
    strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime,
    source,
    eventid,
    JSON_EXTRACT(data, '$.EventData.TargetUserName') AS Targeted_Username,
    JSON_EXTRACT(data, '$.EventData.TargetDomainName') AS Targeted_Domain,
    JSON_EXTRACT(data, '$.EventData.ServiceName') AS Service_Name,
    JSON_EXTRACT(data, '$.EventData.ServiceSid') AS Service_Sid,
    JSON_EXTRACT(data, '$.EventData.TicketOptions') AS Ticket_Option,
    JSON_EXTRACT(data, '$.EventData.TicketEncryptionType') AS Ticket_Encryption,
    JSON_EXTRACT(data, '$.EventData.IpAddress') || CHAR(58) || JSON_EXTRACT(data, '$.EventData.IpPort')  AS IP_port,
    'EVTX Logs' AS Data_Source,
    'T1558.001 Kerberos Service/Auth Ticket Request using RC4' AS Query 
FROM sophos_windows_events
WHERE
    source = 'Security' 
    AND eventid IN (4769, 4768)
    AND Service_Name LIKE '%$'
    AND Ticket_Option IN ('0x40810000','0x40800000','0x40810010') 
    AND Ticket_Encryption IN ('0x17','0x18')