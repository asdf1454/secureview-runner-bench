@echo off
chcp 65001 >nul
cd /d "%~dp0"
if exist "C:\Program Files\Microsoft\jdk-17.0.20.8-hotspot" set "JAVA_HOME=C:\Program Files\Microsoft\jdk-17.0.20.8-hotspot"
set "MAVEN_OPTS=-Dfile.encoding=UTF-8 -Dstdout.encoding=UTF-8"
ollama list >nul 2>&1
call "%~dp0mvnw.cmd" -q compile exec:java "-Dexec.args=examples/UserDao.java 16 89"
echo.
pause
