#!/bin/bash

cd ..

git pull
scp __init__.py logger.py main.py repeated_timer.py rpi_node.py sew_movimot_vfd.py utils.py ubuntu@$1:/home/ubuntu/workspace/rpi-sew-rs485/
ssh ubuntu@$1 "sudo systemctl restart rpi4-sew.service"
ssh ubuntu@$1 sudo date -s @$( (date -u +"%s"))
ssh ubuntu@$1 "sudo timedatectl set-timezone Europe/Warsaw"
