@echo off

if not exist encryption_key.txt (
	echo Error: encryption_key.txt does not exist!
	pause
	exit /b 0
)

set /p KEY=<encryption_key.txt
fpq_pack.exe -c firmware/config -b firmware/u-boot.bin -x firmware/uImage -s firmware/media_app_zip.bin -f firmware/rootfs.cramfs.img -k %KEY% 
pause