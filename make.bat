@echo off
if "%VCVARS%" == "" (
	set "VCVARS=1"
	call vcvarsall x64
)
cl /O2 /Zi /DEBUG /nologo /wd4996 /wd4706 /W4 main.c /Fe:dlsub.exe
