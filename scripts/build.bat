@echo off

:: if no arguments are supplied.
if [%1] NEQ [] (goto code) 

:: print help message if there's no arguments
@echo Usage: %0 "Debug | Release" 
exit /B 1

:code

cd ..

:: Check to see whether the build folder exists.
if exist build\ (
  cd build
  cmake --build . --config %1
) else (
  echo Build folder not created, didn't configure?
  pause
)

cd ../scripts/
