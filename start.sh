#!/bin/sh

echo "------------"
echo " Start cron "
echo "----- ------"

echo "Create crontab configuration"
echo "CRON = $CRON"
echo "$CRON /app/ddiu.py" | crontab -

echo "Starting cron"
crond -f
