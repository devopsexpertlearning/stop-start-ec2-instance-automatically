# stop-ec2-instance-automatically

This repository provides a solution to automatically stop an AWS EC2 instance when it is idle, and start it again when required.

## Overview

The provided shell script checks for recent activity in a specified log file. If no activity is detected within the last 20 minutes, the script stops the EC2 instance. This helps save costs by ensuring that unused instances are not left running.

## Prerequisites

- An AWS EC2 instance.
- An IAM role attached to the EC2 instance with permission to stop the instance.
- AWS CLI installed and configured on the EC2 instance.

## Setup Instructions

### 1. Attach IAM Role

Create or use an existing IAM role with the following permission and attach it to your EC2 instance:

```json
{
  "Effect": "Allow",
  "Action": "ec2:StopInstances",
  "Resource": "*"
}
```

### 2. Ensure AWS CLI is Installed

Install AWS CLI if not already present:

```bash
sudo apt-get update
sudo apt-get install awscli
```

### 3. Create the Shell Script

Create a shell script (e.g., `/usr/local/bin/stop_ec2_if_idle.sh`) with the following content:

```bash
#!/bin/bash
INSTANCE_ID="i-0abc123def456ghij" # Replace with your Instance ID
REGION="us-east-1"                # Replace with your AWS region
LOGFILE="/var/log/ollama.log"     # Replace with your log file path

CUTOFF=$(date -u --date='20 minutes ago' +%s)
LAST_ACTIVITY=""

# Check ISO 8601 lines (time=...)
while read -r line; do
  if [[ $line =~ ^time=([0-9T:\.\-]+)Z ]]; then
    LOGTIME="${BASH_REMATCH[1]}"
    LOG_EPOCH=$(date -u -d "${LOGTIME//T/ }" +%s)
    if (( LOG_EPOCH > CUTOFF )); then
      LAST_ACTIVITY="$line"
    fi
  fi
done < "$LOGFILE"

# Check [GIN] lines
while read -r line; do
  if [[ $line =~ ^\[GIN\]\ ([0-9]{4}/[0-9]{2}/[0-9]{2})\ -\ ([0-9]{2}:[0-9]{2}:[0-9]{2}) ]]; then
    LOGTIME="${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
    LOG_EPOCH=$(date -u -d "$LOGTIME" +%s)
    if (( LOG_EPOCH > CUTOFF )); then
      LAST_ACTIVITY="$line"
    fi
  fi
done < "$LOGFILE"

echo "Checking for activity since $(date -u --date='20 minutes ago' +%Y-%m-%dT%H:%M:%S)"
if [[ -n "$LAST_ACTIVITY" ]]; then
  echo "Recent activity found:"
  echo "$LAST_ACTIVITY"
  echo "Instance will not be stopped."
else
  echo "No recent activity found. Stopping instance $INSTANCE_ID."
  aws ec2 stop-instances --instance-ids $INSTANCE_ID --region $REGION
fi
```

### 4. Make the Script Executable

```bash
sudo chmod +x /usr/local/bin/stop_ec2_if_idle.sh
```

### 5. Test the Script

Run the script manually to ensure it works as expected:

```bash
/usr/local/bin/stop_ec2_if_idle.sh
```

### 6. Schedule with Cron

Edit the crontab to run the script every 5 minutes:

```bash
crontab -e
```

Add the following line:

```
*/5 * * * * /usr/local/bin/stop_ec2_if_idle.sh > /dev/null 2>&1
```

If `crontab` is not installed, install it:

```bash
sudo apt-get install cron
sudo service cron start
```

### 7. Verify the Cron Job

To check if your cron job is running:

- List your current user's cron jobs:

  ```bash
  crontab -l
  ```

  You should see the line you added for the script.

- Check the cron service status:

  ```bash
  sudo service cron status
  ```

- To verify that the script is being executed, you can add logging to your script or check the system logs:

  ```bash
  grep CRON /var/log/syslog
  ```

  (On some systems, use `/var/log/cron` instead.)

## How It Works

- The script checks the specified log file for recent activity.
- If no activity is found in the last 20 minutes, the EC2 instance is stopped automatically.
- The cron job ensures this check runs every 5 minutes.

## Notes

- Update the `INSTANCE_ID`, `REGION`, and `LOGFILE` variables in the script as per your setup.
- Ensure the IAM role has the necessary permissions.
- You can modify the idle timeout by changing the `20 minutes ago` value in the script.

---
