/* ------------------ Sophos.com/RapidResponse ------------------
Check for Exchange zero day patches
----------------------------------------------------------------- */
SELECT 
  f.path,
  h.sha256,
  f.product_version,
  CASE f.product_version
    WHEN '15.0.1497.12'
      THEN 'Patched'
    WHEN '15.1.2106.13'
      THEN 'Patched'
    WHEN '15.1.2176.9'
      THEN 'Patched'
    WHEN '15.2.721.13'
      THEN 'Patched'
    WHEN '15.2.792.10'
      THEN 'Patched'
    ELSE 'NOT_PATCHED'
  END PatchStatus
FROM file AS f LEFT JOIN hash AS h ON f.path = h.path 
WHERE f.path = ((SELECT r.data from registry as r where r.key='HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup' AND r.path='HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup\MsiInstallPath') || 'bin\Microsoft.Exchange.RpcClientAccess.Service.exe')