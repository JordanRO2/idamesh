@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d "%~dp0.."
cl /nologo /Od /Fe:tiny.exe /Fo:src\tiny.obj src\tiny.c
del /q src\tiny.obj 2>nul
