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
  
### 3. Create S3 bucket To Host UI

create s3 bucket with bucket policy and create object index.html

```html
<!DOCTYPE html>
<html>
<head>
    <title>EC2 Control Panel</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {
            background: linear-gradient(135deg, #232526 0%, #ff9966 100%);
            min-height: 100vh;
            margin: 0;
            font-family: 'Segoe UI', Arial, sans-serif;
            color: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: rgba(30, 30, 40, 0.45);
            border-radius: 22px;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.25);
            padding: 2.5rem 2rem 2rem 2rem;
            max-width: 420px;
            width: 100%;
            text-align: center;
            color: #fff;
            backdrop-filter: blur(12px);
            border: 1.5px solid rgba(255, 255, 255, 0.18);
        }
        h2 {
            margin-bottom: 1.5rem;
            color: #ff9966;
            letter-spacing: 1px;
            font-weight: 800;
            font-family: 'Segoe UI', 'Fira Mono', 'Consolas', monospace;
            text-shadow: 0 2px 8px #23252644;
        }
        label {
            display: block;
            margin: 1.2rem 0 0.5rem 0;
            font-size: 1.1rem;
            color: #ff5e62;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        select {
            width: 90%;
            padding: 0.6rem;
            border-radius: 8px;
            border: none;
            margin-bottom: 0.8rem;
            font-size: 1rem;
            background: rgba(255,255,255,0.85);
            color: #ff5e62;
            font-weight: 700;
            box-shadow: 0 2px 8px rgba(255, 94, 98, 0.08);
            outline: none;
            transition: box-shadow 0.2s, background 0.2s;
        }
        select:focus {
            box-shadow: 0 0 0 2px #ff9966;
            background: #fff;
        }
        button {
            background: linear-gradient(90deg, #ff9966 0%, #ff5e62 100%);
            color: #fff;
            border: none;
            border-radius: 8px;
            padding: 0.7rem 1.5rem;
            margin: 0.5rem 0.3rem;
            font-size: 1rem;
            font-weight: 700;
            cursor: pointer;
            box-shadow: 0 2px 8px rgba(255, 94, 98, 0.12);
            transition: background 0.2s, transform 0.2s;
            letter-spacing: 0.5px;
        }
        button:hover {
            background: linear-gradient(90deg, #ff5e62 0%, #ff9966 100%);
            transform: translateY(-2px) scale(1.04);
        }
        #result {
            margin-top: 1.5rem;
            background: rgba(255, 255, 255, 0.10);
            border-radius: 8px;
            padding: 1rem;
            color: #fff;
            font-size: 1.05rem;
            min-height: 2.2rem;
            word-break: break-all;
            font-family: 'Fira Mono', 'Consolas', monospace;
            letter-spacing: 0.5px;
        }
        .spinner-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background: rgba(255, 153, 102, 0.12);
            z-index: 1000;
            display: none;
            align-items: center;
            justify-content: center;
        }
        .spinner {
            border: 6px solid #fff;
            border-top: 6px solid #ff5e62;
            border-radius: 50%;
            width: 48px;
            height: 48px;
            animation: spin 1s linear infinite;
            margin: auto;
        }
        @keyframes spin {
            0% { transform: rotate(0deg);}
            100% { transform: rotate(360deg);}
        }
        #instance-group {
            display: none;
        }
        @media (max-width: 500px) {
            .container {
                padding: 1.2rem 0.5rem 1rem 0.5rem;
                max-width: 98vw;
            }
            h2 {
                font-size: 1.2rem;
            }
            button {
                width: 90%;
                margin: 0.5rem 0;
            }
        }
        /* DevOps accent bar */
        .accent-bar {
            width: 60px;
            height: 6px;
            border-radius: 3px;
            margin: 0 auto 1.5rem auto;
            background: linear-gradient(90deg, #ff9966 0%, #ff5e62 100%);
            box-shadow: 0 2px 8px #ff5e6244;
        }
    </style>
</head>
<body>
    <div class="spinner-overlay" id="spinner-overlay">
        <div class="spinner"></div>
    </div>
    <div class="container">
        <div class="accent-bar"></div>
        <h2>EC2 Instance Control</h2>
        <label for="region">Region:</label>
        <select id="region">
            <option value="">Select region</option>
        </select>
        <div id="instance-group" style="display:none;">
            <label for="instance">Instance:</label>
            <select id="instance"></select>
        </div>
        <div>
            <button onclick="startInstance()">Start</button>
            <button onclick="stopInstance()">Stop</button>
            <button onclick="getIPs()">Get IPs</button>
        </div>
        <div id="result"></div>
    </div>
    <script>
        const apiBase = "https://zd0420hz7k.execute-api.ap-east-1.amazonaws.com";
        function showSpinner(show) {
            document.getElementById("spinner-overlay").style.display = show ? "flex" : "none";
        }

        async function fetchRegions() {
            showSpinner(true);
            const sel = document.getElementById("region");
            sel.innerHTML = '<option value="">Select region</option>';
            document.getElementById("instance-group").style.display = "none";
            document.getElementById("result").innerText = ""; 
            
            try {
                const res = await fetch(apiBase + "/regions");
                const rawData = await res.text();
                
                // Parse the response based on what we received
                let regions = [];
                try {
                    const data = JSON.parse(rawData);
                    if (Array.isArray(data)) {
                        regions = data;
                    } else if (data && data.body) {
                        if (typeof data.body === 'string') {
                            regions = JSON.parse(data.body);
                        } else if (Array.isArray(data.body)) {
                            regions = data.body;
                        }
                    }
                } catch (e) {
                    // Silent error handling
                }
                
                // Sort regions alphabetically
                regions.sort();
                
                regions.forEach(r => {
                    const opt = document.createElement("option");
                    opt.value = r;
                    opt.text = r;
                    sel.appendChild(opt);
                });
            } catch (e) {
                sel.innerHTML = '<option value="">Error loading regions</option>';
            }
            showSpinner(false);
        }

        async function fetchInstances(region) {
            const sel = document.getElementById("instance");
            const group = document.getElementById("instance-group");
            sel.innerHTML = "<option>Loading...</option>";
            group.style.display = "none";
            if (!region) {
                sel.innerHTML = "";
                return;
            }
            showSpinner(true);
            try {
                const res = await fetch(apiBase + "/instances?region=" + encodeURIComponent(region));
                const rawData = await res.text();
                
                // Parse the response based on what we received
                let instances = [];
                try {
                    const data = JSON.parse(rawData);
                    if (Array.isArray(data)) {
                        instances = data;
                    } else if (data && data.body) {
                        if (typeof data.body === 'string') {
                            instances = JSON.parse(data.body);
                        } else if (Array.isArray(data.body)) {
                            instances = data.body;
                        }
                    }
                } catch (e) {
                    // Silent error handling
                }
                
                sel.innerHTML = "";
                if (instances.length === 0) {
                    sel.innerHTML = "<option>No instances found</option>";
                } else {
                    instances.forEach(i => {
                        const opt = document.createElement("option");
                        opt.value = i.InstanceId;
                        opt.text = `${i.InstanceId} - ${i.InstanceType} ${i.Name ? `(${i.Name})` : ''} [${i.State}]`;
                        sel.appendChild(opt);
                    });
                }
                group.style.display = "block";
            } catch (e) {
                sel.innerHTML = "<option>Error loading instances</option>";
            }
            showSpinner(false);
        }

        async function startInstance() {
            showSpinner(true);
            document.getElementById("result").innerText = "Starting instance...";
            const region = document.getElementById("region").value;
            const instance_id = document.getElementById("instance").value;
            if (!region || !instance_id) {
                document.getElementById("result").innerText = "Please select region and instance.";
                showSpinner(false);
                return;
            }
            try {
                const res = await fetch(apiBase + "/start", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({region, instance_id})
                });
                const data = await res.json();
                let resultText = data.message || "Unknown response";
                
                // Add IP information if available
                if (data.public_ip || data.private_ip) {
                    resultText += `\nPublic IP: ${data.public_ip || "N/A"}`;
                    resultText += `\nPrivate IP: ${data.private_ip || "N/A"}`;
                }
                
                document.getElementById("result").innerText = resultText;
            } catch (e) {
                document.getElementById("result").innerText = "Error starting instance.";
            }
            showSpinner(false);
        }

        async function stopInstance() {
            showSpinner(true);
            document.getElementById("result").innerText = "Stopping instance...";
            const region = document.getElementById("region").value;
            const instance_id = document.getElementById("instance").value;
            if (!region || !instance_id) {
                document.getElementById("result").innerText = "Please select region and instance.";
                showSpinner(false);
                return;
            }
            try {
                const res = await fetch(apiBase + "/stop", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({region, instance_id})
                });
                const data = await res.json();
                document.getElementById("result").innerText = data.message || data.error || "Unknown response";
            } catch (e) {
                document.getElementById("result").innerText = "Error stopping instance.";
            }
            showSpinner(false);
        }

        async function getIPs() {
            showSpinner(true);
            document.getElementById("result").innerText = "Fetching IP addresses...";
            const region = document.getElementById("region").value;
            const instance_id = document.getElementById("instance").value;
            if (!region || !instance_id) {
                document.getElementById("result").innerText = "Please select region and instance.";
                showSpinner(false);
                return;
            }
            try {
                const res = await fetch(apiBase + "/get", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({region, instance_id})
                });
                const data = await res.json();
                if (data.public_ip || data.private_ip) {
                    document.getElementById("result").innerText =
                        `Public IP: ${data.public_ip || "N/A"}\nPrivate IP: ${data.private_ip || "N/A"}`;
                } else {
                    document.getElementById("result").innerText = data.message || data.error || "No IP information available";
                }
            } catch (e) {
                document.getElementById("result").innerText = "Error fetching IPs.";
            }
            showSpinner(false);
        }

        document.getElementById("region").addEventListener("change", function() {
            const region = this.value;
            if (region) {
                fetchInstances(region);
            } else {
                document.getElementById("instance-group").style.display = "none";
                document.getElementById("instance").innerHTML = "";
            }
        });

        window.onload = fetchRegions;
    </script>
</body>
</html>

```
