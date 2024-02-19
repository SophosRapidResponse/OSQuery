/*************************** Sophos.com/RapidResponse ***************************\
|                                                                                |
| DESCRIPTION                                                                    |
| Looks for the last part of the ProxyShell exploit where a new mailbox is       |
| created and used to drop the webshell on the Exchange server. The usernames    |
| involved are for reference only, they aren't actually compromised.             |
|                                                                                |
| MORE INFO                                                                      |
| shorturl.at/dnrCS - ProxyShell vulnerabilities in Microsoft Exchange           |
|                                                                                |
| Version: 1.2                                                                   |
| Author: @AltShiftPrtScn & Karl the Hack Ackerman                               |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

WITH Event_Data(Event_id, time, Data) AS (
SELECT eventid, time, JSON_EXTRACT(swe.data, '$.EventData.Data') AS Data
FROM sophos_windows_events swe
WHERE time > strftime('%s', 'now', '-180 days')
AND source = 'MSExchange Management'
AND (
data LIKE '%New-MailboxExportRequest%' OR
data LIKE '%Set-OabVirtualDirectory%' OR
data LIKE '%New-ExchangeCertificate%' OR
data LIKE '%Add-RoleGroupMember%' OR
data LIKE 'Add-MailboxPermission%' OR
data LIKE '%HiddenFromAddressListsEnabled%' OR
data LIKE '%New-ManagementRoleAssignment%')
)

SELECT
   REPLACE(datetime(time, 'unixepoch'),' ','T')||'Z' Date_Time,
   event_id,
   REPLACE(SPLIT(Data,',',0), ',', '') AS Mailbox,
   SPLIT(Data,'\"',1) AS Email,
   CASE
   WHEN REPLACE(SPLIT(Data,',',0), ',', '') = 'New-ExchangeCertificate' THEN Data
   ELSE REPLACE(REPLACE(REPLACE(SPLIT(Data,'\"',5), '(Subject -eq ', ''), ')', ''), CHAR(39), '') END AS Subject,
   substr(SPLIT(SPLIT(Data,',',1),'-',5),9) WebShell,
   SPLIT(Data,',',2) AS User,
   SPLIT(Data,',',3) AS SID,
   'MSExchange Management EVTX' AS Data_Source,
   'ProxyShell.02.0' AS Query
FROM Event_Data