/* ------------------ Sophos.com/RapidResponse ------------------
Potential webshells related to Hafnium
----------------------------------------------------------------- */
SELECT
   filename, directory, strftime('%Y-%m-%dT%H:%M:%SZ',datetime(btime,'unixepoch') AS created_time,
   size AS fileSize,
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(atime, 'unixepoch') AS access_time,
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime, 'unixepoch') AS modified_time
FROM file
WHERE
(path LIKE 'C:\inetpub\wwwroot\%%' 
or path LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\%%'
or path LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\ecp\auth\%%'
and filename in ('web.aspx' ,'help.aspx','document.aspx','errorEE.aspx','errorEEE.aspx','errorEW.aspx','errorFF.aspx','web.aspx','healthcheck.aspx','aspnet_www.aspx','aspnet_client.aspx','xx.aspx','shell.aspx','aspnet_iisstart.aspx','one.aspx','errorcheck.aspx','t.aspx','discover.aspx','aspnettest.aspx','error.aspx','RedirSuiteServerProxy.aspx','shellex.aspx','supp0rt.aspx','HttpProxy.aspx','system_web.aspx','OutlookEN.aspx','Logout.aspx','OutlookJP.aspx','MultiUp.aspx','OutlookRU.aspx','log.aspx','load.aspx'))
UNION
SELECT
   regex_match(filename, '[0-9a-zA-Z]{8}.aspx', 0) AS filename, directory, strftime('%Y-%m-%dT%H:%M:%SZ',datetime(btime,'unixepoch') AS created_time,
   size AS fileSize,
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(atime, 'unixepoch') AS access_time,
   strftime('%Y-%m-%dT%H:%M:%SZ',datetime(mtime, 'unixepoch') AS modified_time
FROM file
WHERE (path LIKE 'C:\inetpub\wwwroot\%%' OR path LIKE 'C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\%%') AND filename IS NOT NULL
ORDER by filename;