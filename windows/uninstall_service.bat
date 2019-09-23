@echo off

set SERVICE_NAME=http-proxy

sc delete "%SERVICE_NAME%"  

pause

@echo on