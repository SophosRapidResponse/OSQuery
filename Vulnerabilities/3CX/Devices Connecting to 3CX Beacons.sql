/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identify devices making connection to the malicious 3Cx beacons.               |
| Query uses sophos journals                                                     |
|                                                                                |
| VARIABLES                                                                      |
| - start_time (type DATE)                                                       |
| - end_time (type DATE)                                                         |
|                                                                                |
| REFERENCE                                                                      |
| https://news.sophos.com/en-us/2023/03/29/3cx-dll-sideloading-attack/           |
| https://www.3cx.com/blog/news/desktopapp-security-alert/                       |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT 
strftime('%Y-%m-%dT%H:%M:%SZ',datetime(spa.time,'unixepoch')) AS date_time,
sophos_process_journal.process_name,
spa.sophos_pid, 
spa.object,
'Devices Connecting to 3CX Beacons' AS query
FROM sophos_process_activity spa
LEFT JOIN sophos_process_journal USING (sophos_pid)
WHERE spa.time >= $$start_time$$ 
AND spa.time <= $$end_time$$ 
AND spa.subject IN ('Dns','Url','Http','ModernWebFlow')
AND (spa.object IN ('akamaicontainer.com', 'akamaitechcloudservices.com', 'azuredeploystore.com', 'azureonlinestorage.com', 'azureonlinecloud.com', 'dunamistrd.com', 'glcloudservice.com', 'journalide.org', 'msedgepackageinfo.com', 'msstorageazure.com', 'msstorageboxes.com', 'officeaddons.com','pbxcloudeservices.com','officestoragebox.com', 'pbxphonenetwork.com', 'pbxsources.com', 'qwepoi123098.com', 'sbmsa.wiki', 'sourceslabs.com', 'visualstudiofactory.com', 'zacharryblogs.com')
OR spa.object LIKE '%/iconstorages/images/main/%')
