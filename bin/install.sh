#!/bin/bash
if [ -f "mav.tar" ]
then
	sudo rm -f mav.tar
fi
if [ -d "/usr/src/mindrun/mav/" ]
then
	sudo rm -f /usr/src/mindrun/mav/
fi
sudo wget https://av.mindrun.de/downloads/mav/mav-latest.tar
sudo tar -xf mav-latest.tar
sudo rm -f mav-latest.tar
sudo mkdir -p /usr/src/mindrun/
sudo mv mav/ /usr/src/mindrun/
if [ -f "/usr/bin/mavscan" ]
then
	sudo rm -f /usr/bin/mavscan
fi
sudo ln -sf /usr/src/mindrun/mav/cli.php /usr/bin/mavscan
if [ -f "/usr/bin/mavscan" ]
then
	echo "MAVscan successfully installed in /usr/bin/mavscan."
fi
