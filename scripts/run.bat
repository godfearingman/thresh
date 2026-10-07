@echo off 

:: if no arguments are supplied.
if [%1] NEQ [] (goto code) 

:: print help message if there's no arguments
@echo Usage: %0 "Debug | Release" 
exit /B 1

:code
:: compile the program.
call build.bat %1
:: run the produced file.
cd ..
cd build\%1\
start "" thresh.exe

cd ../../scripts

