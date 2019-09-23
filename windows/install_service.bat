@echo off

set SERVICE_NAME=http-proxy
set SERVICE_DESCRIPTION=Http proxy. With http-proxy, you can assign a socks5 proxy as upstream proxy, and, use "chnroute" to by pass proxy.

SET CONFIG_FILE=http-proxy.config

set CURR_PATH=%~dp0

if not exist "%CURR_PATH%%CONFIG_FILE%" (
	(
		echo.
		echo config cfg
		echo 	option bind_addr '127.0.0.1'
		echo 	option bind_port '1081'
		echo 	option chnroute '%CURR_PATH%lan.txt,%CURR_PATH%chnroute.txt,%CURR_PATH%chnroute6.txt'
		echo 	option timeout '30'
		echo 	option log_file '%CURR_PATH%http-proxy.log'
		echo 	option log_level '5'
		echo 	#option proxy '127.0.0.1:1080'
	)> "%CURR_PATH%%CONFIG_FILE%"
)

sc create "%SERVICE_NAME%" binpath= "\"%CURR_PATH%http-proxy.exe\" --daemon --config=\"%CURR_PATH%%CONFIG_FILE%\" --launch-log=\"%CURR_PATH%http-proxy-launch-log.log\"" displayname= "%SERVICE_NAME%" depend= Tcpip start= auto  

sc description "%SERVICE_NAME%" "%SERVICE_DESCRIPTION%"

pause

@echo on
