
/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Identify devices making connection to the malicious 3Cx beacons.               |
|                                                                                |
| REFERENCE                                                                      |
| https://news.sophos.com/en-us/2023/03/29/3cx-dll-sideloading-attack/           |
| https://www.3cx.com/blog/news/desktopapp-security-alert/                       |
| Version: 1.0                                                                   |
| Author: MDR OPs                                                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


SELECT DISTINCT
meta_hostname, pids, sophos_pids, domain, clean_urls
FROM
  xdr_ext_data
WHERE
  licence = 'MTR'
AND query_name = 'sophos_urls_windows'
	AND( LOWER(domain) LIKE '%akamaicontainer%'
	OR LOWER(domain) LIKE '%akamaitechcloudservices%'
	OR LOWER(domain) LIKE '%azuredeploystore%'
	OR LOWER(domain) LIKE '%azureonlinecloud%'
	OR LOWER(domain) LIKE '%azureonlinestorage%'
	OR LOWER(domain) LIKE '%dunamistrd%'
	OR LOWER(domain) LIKE '%glcloudservice%'
	OR LOWER(domain) LIKE '%journalide%'
	OR LOWER(domain) LIKE '%msedgepackageinfo%'
	OR LOWER(domain) LIKE '%msstorageazure%'
	OR LOWER(domain) LIKE '%msstorageboxes%'
	OR LOWER(domain) LIKE '%officeaddons%'
	OR LOWER(domain) LIKE '%officestoragebox%'
	OR LOWER(domain) LIKE '%pbxcloudeservices%'
	OR LOWER(domain) LIKE '%pbxphonenetwork%'
	OR LOWER(domain) LIKE '%pbxsources%'
	OR LOWER(domain) LIKE '%qwepoi123098%'
	OR LOWER(domain) LIKE '%sbmsa%'
	OR LOWER(domain) LIKE '%sourceslabs%'
	OR LOWER(domain) LIKE '%visualstudiofactory%'
	OR LOWER(domain) LIKE '%zacharryblogs%'
	OR LOWER(clean_urls) LIKE '%/iconstorages/images/main/%')
ORDER BY meta_hostname