#!/bin/sh

echo "------------"
echo " Execute ddiu a first time"
echo "------------"
/app/ddiu.py

echo "------------"
echo " Start cron "
echo "------------"

echo "Create crontab configuration"
echo "CRON = $CRON"
echo "$CRON /app/ddiu.py" | crontab -

echo "Starting cron"
crond -f
