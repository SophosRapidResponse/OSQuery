/*************************** Sophos.com/RapidResponse ***************************\
| DESCRIPTION                                                                    |
| This query was created for grepping the WSO2 product's webserver logs to search|
| for suspicious requests that might be indicative of malicious webshell upload  | 
|                                                                                |
| VARIABLES                                                                      |
| - $$directory$$ (string): complete path to WSO2 http_access directory          |
| - $$pattern$$ (string)                                                         |
|                                                                                |
| TIP                                                                            |
| For $$pattern$$ you can use the following strings:                             |
|  - /fileupload/toolsAny                                                        |
|  - powershell                                                                  |
|  - .war, .jsp                                                                  |
|                                                                                |
| REFERENCE                                                                      |
| https://www.rapid7.com/blog/post/2022/04/22/opportunistic-exploitation-of-wso2-|
| cve-2022-29464/                                                                |
|                                                                                |
| Version: 1.0                                                                   |
| Author: The Rapid Response Team |Lee Kikpatrick                                |
| github.com/SophosRapidResponse                                                 |
\********************************************************************************/


-- GET a list of files
WITH File_List AS (SELECT path,filename FROM file WHERE path LIKE '$$directory$$%')


-- Grep the list of files
SELECT
f.path as Path,
f.filename as Filename,
(SELECT 
	CAST(GROUP_CONCAT(DISTINCT(regex_match(g.line,'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',0))||CHAR(10)) AS text)
	FROM grep g 
	WHERE g.pattern IN ('$$pattern$$') AND g.path = f.path 
	) As IP_match,
(SELECT 
	CAST(GROUP_CONCAT(g.line,CHAR(10)) AS TEXT) 
	FROM grep g 
	WHERE g.pattern IN ('$$pattern$$') AND g.path = f.path 
	) As Line
FROM File_List f
WHERE f.filename LIKE '%.log%'
AND Line != ''
