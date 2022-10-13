git pull
scp rpi-sew-rs485.py utils.py logger.py timer.py ubuntu@$1:/home/ubuntu/workspace/rpi-sew-rs485/
ssh ubuntu@$1 "sudo systemctl restart rpi4-sew.service"
ssh ubuntu@$1 sudo date -s @`( date -u +"%s" )`
ssh ubuntu@$1 "sudo timedatectl set-timezone Europe/Warsaw"