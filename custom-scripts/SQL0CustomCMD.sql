USE [master]
GO

CREATE LOGIN [@domain\sp_farm] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
CREATE LOGIN [@domain\sp_svcpool] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
CREATE LOGIN [@domain\sp_webpool] FROM WINDOWS WITH DEFAULT_DATABASE=[master], DEFAULT_LANGUAGE=[us_english]
GO

ALTER SERVER ROLE [securityadmin] ADD MEMBER [@domain\sp_farm]
ALTER SERVER ROLE [dbcreator] ADD MEMBER [@domain\sp_farm]
GO
