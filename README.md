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

# start-ec2-instance-automatically

## Setup Instructions

### 1. Create Lamda Function 
Create lambda function with code and select runtime env python 3. File name should be lambda_function.py

  ```python
  import os
import json
import logging
import boto3
from botocore.exceptions import ClientError, WaiterError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def get_regions():
    ec2 = boto3.client("ec2")
    resp = ec2.describe_regions(AllRegions=True)
    return [r["RegionName"] for r in resp["Regions"] if r["OptInStatus"] in ("opt-in-not-required", "opted-in")]

def get_instances(region):
    ec2 = boto3.client("ec2", region_name=region)
    resp = ec2.describe_instances()
    instances = []
    for res in resp["Reservations"]:
        for inst in res["Instances"]:
            name = ""
            for tag in inst.get("Tags", []):
                if tag["Key"] == "Name":
                    name = tag["Value"]
            instances.append({
                "InstanceId": inst["InstanceId"],
                "Name": name,
                "InstanceType": inst["InstanceType"],
                "State": inst["State"]["Name"]
            })
    return instances

def start_instance(region, instance_id):
    ec2 = boto3.client("ec2", region_name=region)
    ec2.start_instances(InstanceIds=[instance_id])

def stop_instance(region, instance_id):
    ec2 = boto3.client("ec2", region_name=region)
    ec2.stop_instances(InstanceIds=[instance_id])

def wait_for_instance_running(region, instance_id, timeout=120):
    ec2 = boto3.client("ec2", region_name=region)
    waiter = ec2.get_waiter("instance_running")
    try:
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 5, "MaxAttempts": timeout // 5})
    except Exception as e:
        logger.error(f"Error waiting for instance to run: {e}")

def get_instance_ips(region, instance_id):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        instance = resp["Reservations"][0]["Instances"][0]
        public_ip = instance.get("PublicIpAddress")
        private_ip = instance.get("PrivateIpAddress")
        return public_ip, private_ip
    except Exception as e:
        logger.error(f"Error fetching IPs: {e}")
        return None, None

def get_instance_state(region, instance_id):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        instance = resp["Reservations"][0]["Instances"][0]
        return instance["State"]["Name"]
    except Exception as e:
        logger.error(f"Error getting instance state: {e}")
        return None

def lambda_handler(event, context):
    # Log the event for debugging
    logger.info(f"Received event: {json.dumps(event)}")
    
    # API Gateway V2 format paths are in rawPath
    path = event.get("rawPath", "")
    
    # API Gateway V2 method is in requestContext.http.method
    http_method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    
    params = event.get("queryStringParameters") or {}
    raw_body = event.get("body")
    is_base64 = event.get("isBase64Encoded", False)
    
    # Handle base64 encoded body (common in API Gateway V2)
    body = {}
    if raw_body:
        if is_base64:
            import base64
            raw_body = base64.b64decode(raw_body).decode('utf-8')
        
        if isinstance(raw_body, str):
            try:
                body = json.loads(raw_body)
            except Exception as e:
                logger.error(f"Error parsing body: {e}")
        elif isinstance(raw_body, dict):
            body = raw_body

    logger.info(f"Processing API Gateway V2 request: {http_method} {path}")
    logger.info(f"Body: {json.dumps(body)}")
    
    # CORS headers for API Gateway V2
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization"
    }

    try:
        if path == "/regions":
            regions = get_regions()
            return {"statusCode": 200, "headers": headers, "body": json.dumps(regions)}
        elif path == "/instances":
            region = params.get("region")
            if not region:
                return {"statusCode": 400, "body": "Missing region"}
            instances = get_instances(region)
            return {"statusCode": 200, "headers": headers, "body": json.dumps(instances)}
        elif path == "/start" and http_method == "POST":
            region = body.get("region")
            instance_id = body.get("instance_id")
            if not region or not instance_id:
                return {"statusCode": 400, "headers": headers, "body": json.dumps({"error": "Missing region or instance_id"})}
            
            # Check if instance is already running
            state = get_instance_state(region, instance_id)
            if state == "running":
                public_ip, private_ip = get_instance_ips(region, instance_id)
                return {
                    "statusCode": 200,
                    "headers": headers,
                    "body": json.dumps({
                        "message": "Instance is already running",
                        "public_ip": public_ip,
                        "private_ip": private_ip
                    })
                }
            
            start_instance(region, instance_id)
            wait_for_instance_running(region, instance_id)
            
            # Wait for IP to be assigned
            public_ip, private_ip = None, None
            import time
            for _ in range(6):
                public_ip, private_ip = get_instance_ips(region, instance_id)
                if public_ip:
                    break
                time.sleep(5)
                
            return {
                "statusCode": 200, 
                "headers": headers,
                "body": json.dumps({
                    "message": "Instance started successfully",
                    "public_ip": public_ip,
                    "private_ip": private_ip
                })
            }
        elif path == "/stop" and http_method == "POST":
            region = body.get("region")
            instance_id = body.get("instance_id")
            if not region or not instance_id:
                return {"statusCode": 400, "headers": headers, "body": json.dumps({"error": "Missing region or instance_id"})}
            
            # Check if instance is already stopped/stopping
            state = get_instance_state(region, instance_id)
            if state in ["stopped", "stopping"]:
                return {
                    "statusCode": 200,
                    "headers": headers,
                    "body": json.dumps({
                        "message": f"Instance is already {state}"
                    })
                }
                
            stop_instance(region, instance_id)
            return {
                "statusCode": 200, 
                "headers": headers, 
                "body": json.dumps({"message": "Instance stopped successfully"})
            }
        elif path == "/get" and http_method == "POST":
            region = body.get("region")
            instance_id = body.get("instance_id")
            if not region or not instance_id:
                return {"statusCode": 400, "body": "Missing region or instance_id"}
            public_ip, private_ip = get_instance_ips(region, instance_id)
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps({
                    "public_ip": public_ip,
                    "private_ip": private_ip
                })
            }
        else:
            return {"statusCode": 404, "headers": headers, "body": json.dumps({"error": f"Not found: {path}"})}
    except Exception as e:
        logger.error(f"Error: {e}")
        return {"statusCode": 500, "headers": headers, "body": json.dumps({"error": str(e)})}
  ```
#### Note: During lambda creation you need to create Role which should have access on EC2, cloudwatch logs.

### 2. Create AWS API Gateway 

Select create HTTP AWS API Gateway with following routes and integrate Lambda function what create in previous step.

- /regions - Method 'GET'
- /instances - Method 'GET'
- /start - Method 'POST'
-  /stop - Method 'POST'
- /get - Method 'POST'

