/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets AV detections events in Windows Event logs.                               |
| It currently collects events from Sophos, Windows Defender, Symantec, and 	 |
| Carbon Black that are stored in (Application, Windows Defender/Operational)    |
|                                                                                |
|                                                                                |
| Version: 1.0                                                                   |
| Author: Sophos Rapid Response Team                                    	     |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/

SELECT
	strftime('%Y-%m-%dT%H:%M:%SZ',datetime) AS Datetime,
	source AS Source,
	provider_name AS Provider_Name,
	eventid AS Event_ID,
	CASE
	WHEN eventid='1006' THEN 'Malware or other potentially unwanted software found'
	WHEN eventid='1007' THEN 'Action performed to protect your system from malware or other potentially unwanted software'
	WHEN eventid='1008' THEN 'Failed attempt to perform an action to protect your system from malware or other potentially unwanted software'
	WHEN eventid='1009' THEN 'Item from quarantine restored'
	WHEN eventid='1116' THEN 'Malware or other potentially unwanted software detected'
	WHEN eventid='1117' THEN 'Action performed to protect your system from malware or other potentially unwanted software'
	WHEN eventid='1118' THEN 'Failed attempt to perform an action to protect your system from malware or other potentially unwanted software'
	WHEN eventid='33' THEN 'Threat detected by Carbon Black'
	WHEN eventid='5' THEN 'Symantec Antivirus scan detected a virus.'
	WHEN eventid='47' THEN 'Symantec Antivirus took action against a detected threat.'
	WHEN eventid='51' THEN 'Symantec Antivirus finished handling a threat.'
	ELSE 'Other' END as Description,
	data AS Data,
	'EVTX' AS Data_Source,
	'AV Detections' AS Query
FROM sophos_windows_events 
WHERE source = 'Microsoft-Windows-Windows Defender/Operational' AND eventid in ('1006', '1007', '1008', '1009', '1010', '1011' , '1116' , '1117' , '1118')
	OR source = 'Application' AND provider_name LIKE '%Sophos%' AND eventid = '42'
	OR source = 'Application' AND provider_name LIKE '%Symantec%' AND eventid in ('5','47','51')
	OR source = 'Application' AND provider_name LIKE '%CbDefense%' AND eventid in ('17','33','49')