@echo off
set JAVA_HOME=C:\PROGRA~1\JAVA\JDK-12
set M2_HOME=c:\tools\apache-maven-3.6.0
set JARFILE=target\Study09-1.0.0-SNAPSHOT.jar
set MAINCLASS=kp.MainApp09
pushd %cd%
cd ..
call %M2_HOME%\bin\mvn clean install
chcp 65001
echo.
%JAVA_HOME%\bin\java -Dfile.encoding=UTF-8 -cp %JARFILE% %MAINCLASS%
pause
popd