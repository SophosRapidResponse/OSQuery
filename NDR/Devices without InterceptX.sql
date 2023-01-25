/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| Gets a list of unmanaged devices by Sophos Central based on MDNS and NetBIOS   |
| correlation                                                                    |
|                                                                                |
| VARIABLE                                                                       |
| - Source IP           (type: IP Address)                                       |
| - Source MAC Address  (type: String)                                           |
| - Web_hostname        (type: Device Name)                                      |
|                                                                                |
| TIP                                                                            |
| Use wildcard (%) to get a list of all unmanaged machines in the enviroment     |
|                                                                                |
| Version: 1.0                                                                   |
| Author: Karl Ackerman                                                          |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


WITH NDR_Data AS (
    SELECT
    CAST(JSON_EXTRACT(raw,'$.ingest_date') AS VARCHAR) Day,
    CAST(JSON_EXTRACT(raw,'$.description') AS VARCHAR) Description, -- Detection Context
    REPLACE(CAST(JSON_EXTRACT(raw,'$.detection_context['||CAST(A.x AS VARCHAR)||'].src_ip') AS VARCHAR),',',','||CHR(10)) Source_IP_List,
    CAST(JSON_EXTRACT(raw,'$.detection_context['||CAST(A.x AS VARCHAR)||'].src_mac') AS VARCHAR) Source_MAC_Address,
    REPLACE(CAST(JSON_EXTRACT(raw,'$.detection_context['||CAST(A.x AS VARCHAR)||'].web_hostname') AS VARCHAR),',',','||CHR(10)) Web_Hostname_List
    FROM mdr_ioc_all, UNNEST(SEQUENCE(0,JSON_ARRAY_LENGTH(JSON_EXTRACT(raw,'$.detection_context'))-1)) AS A(x)
    WHERE ioc_detection_id LIKE 'NDR%'
    AND CAST(JSON_EXTRACT(raw, '$.name') AS VARCHAR) = 'MacIpHostnameCorrelation'
    AND LOWER(CAST(JSON_EXTRACT(raw,'$.detection_context['||CAST(A.x AS VARCHAR)||'].src_ip') AS VARCHAR)) LIKE LOWER('%$$Source IP$$%')
    AND LOWER(CAST(JSON_EXTRACT(raw,'$.detection_context['||CAST(A.x AS VARCHAR)||'].src_mac') AS VARCHAR)) LIKE LOWER('%$$Source MAC Address$$%')
    AND LOWER(CAST(JSON_EXTRACT(raw,'$.detection_context['||CAST(A.x AS VARCHAR)||'].web_hostname') AS VARCHAR)) LIKE LOWER('%$$Web_hostname$$%')
    GROUP BY 1,2,3,4,5
)

SELECT
    NDR.Day,
    NDR.Description,
    ARRAY_JOIN(ARRAY_DISTINCT(SPLIT(REPLACE(ARRAY_JOIN(ARRAY_AGG(DISTINCT NDR.Source_IP_List),CHR(10)),',',''),CHR(10))),CHR(10)) Source_IP_List,
    NDR.Source_Mac_Address,
    ARRAY_JOIN(ARRAY_DISTINCT(SPLIT(REPLACE(ARRAY_JOIN(ARRAY_AGG(DISTINCT NDR.Web_Hostname_List),CHR(10)),',',''),CHR(10))),CHR(10)) Web_Hostname_List
FROM NDR_Data NDR
LEFT JOIN xdr_data XDR ON LOWER(XDR.meta_mac_address) = LOWER(NDR.Source_Mac_Address)
    AND XDR.stream_ingest_date = NDR.Day
WHERE XDR.meta_hostname IS NULL
GROUP BY 1,2,4
ORDER BY NDR.Day DESC