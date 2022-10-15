#!/bin/bash

ssh ubuntu@$1 "sudo systemctl stop rpi4-sew.service"
ssh ubuntu@$1 "sudo systemctl daemon-reload"
ssh ubuntu@$1 "rm /home/ubuntu/workspace/rpi-sew-rs485/*.py"
