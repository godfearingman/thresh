@echo off

cd ..
:: I don't specify a generator, may need to do that later.
cmake -B build/
cd scripts
