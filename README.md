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
Create lambda function with code and select runtime env python 3. File name should be lambda_function.py or

Download full lambda zip code ref. https://devopsexpert-shared.s3.ap-south-1.amazonaws.com/lambda_deployment.zip with Cognito Authentication.

  ```python
import os
import json
import logging
import boto3
import base64
import time
from botocore.exceptions import ClientError, WaiterError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Flag to track if jose module is available
jwt_validation_available = False

try:
    from jose import jwk, jwt
    from jose.utils import base64url_decode
    import urllib.request
    jwt_validation_available = True
    logger.info("JWT validation is available")
except ImportError:
    logger.warning("JWT validation is not available - missing jose module")

# Cognito configuration from environment variables
REGION = os.environ.get('COGNITO_REGION')
USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')
APP_CLIENT_ID = os.environ.get('COGNITO_APP_CLIENT_ID')

# Add validation to ensure environment variables are set
if not REGION or not USER_POOL_ID or not APP_CLIENT_ID:
    logger.critical("Missing required Cognito environment variables")
    # This will cause the function to fail if env vars are missing
    # You could also set jwt_validation_available to False instead

# Global variables for caching
jwks = None
jwks_last_updated = 0

def get_jwks():
    """
    Get the JSON Web Key Set (JWKS) from Cognito
    """
    if not jwt_validation_available:
        return None
    
    global jwks, jwks_last_updated
    
    # Cache JWKS for 24 hours
    if jwks is None or time.time() - jwks_last_updated > 86400:
        try:
            # Use the correct URL format for Cognito JWKS
            jwks_url = f'https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json'
            logger.info(f"Fetching JWKS from URL: {jwks_url}")
            
            with urllib.request.urlopen(jwks_url) as f:
                jwks = json.loads(f.read().decode('utf-8'))
                jwks_last_updated = time.time()
                logger.info("JWKS retrieved successfully")
        except Exception as e:
            logger.error(f"Error retrieving JWKS: {str(e)}")
            # Add fallback behavior - return empty JWKS
            jwks = {"keys": []}
            return jwks
    
    return jwks
def validate_cognito_token(token):
    """
    Validate the Cognito JWT token
    """
    try:
        # If JWT validation is not available, deny access
        if not jwt_validation_available:
            logger.critical("JWT validation not available - security risk!")
            return False
        
        if not token:
            logger.warning("No token provided")
            return False
        
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token[7:]
        
        # Get the kid (key ID) from the token
        headers = jwt.get_unverified_header(token)
        kid = headers['kid']
        
        # Get the JWKS
        jwks = get_jwks()
        if not jwks or not jwks.get("keys"):
            logger.error("Failed to retrieve JWKS or empty JWKS returned")
            return False
        
        # Get the public key that matches the kid
        public_key = None
        for key in jwks['keys']:
            if key['kid'] == kid:
                public_key = key
                break
        
        if not public_key:
            logger.warning(f"Public key not found for kid: {kid}")
            return False
        
        # Verify the token
        # Get the last two sections of the token (payload and signature)
        message, encoded_signature = token.rsplit('.', 1)
        
        # Decode the signature
        decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
        
        # Build the public key
        public_key = jwk.construct(public_key)
        
        # Verify the signature
        if not public_key.verify(message.encode('utf-8'), decoded_signature):
            logger.warning("Signature verification failed")
            return False
        
        # Verify the claims
        claims = jwt.get_unverified_claims(token)
        
        # Check token expiration
        if time.time() > claims['exp']:
            logger.warning("Token has expired")
            return False
        
        # Verify the audience (client ID)
        if claims.get('client_id') != APP_CLIENT_ID and claims.get('aud') != APP_CLIENT_ID:
            client_id = claims.get('client_id', claims.get('aud', 'unknown'))
            logger.warning(f"Token was not issued for this app: {client_id} != {APP_CLIENT_ID}")
            return False
        
        # Verify the issuer
        expected_issuer = f'https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}'
        if claims['iss'] != expected_issuer:
            logger.warning(f"Issuer {claims['iss']} does not match {expected_issuer}")
            return False
        
        # Token is valid
        return True
    
    except Exception as e:
        logger.warning(f"Token validation error: {str(e)}")
        return False

def get_user_info_from_token(token):
    """
    Extract user information from the token
    """
    if not jwt_validation_available:
        return {"username": "unknown", "email": "unknown"}
    
    if not token:
        return None
    
    # Remove 'Bearer ' prefix if present
    if token.startswith('Bearer '):
        token = token[7:]
    
    try:
        # Get claims without full validation
        claims = jwt.get_unverified_claims(token)
        return {
            "username": claims.get("cognito:username", claims.get("username", "unknown")),
            "email": claims.get("email", "unknown"),
            "exp": claims.get("exp", 0)
        }
    except Exception as e:
        logger.warning(f"Error extracting user info from token: {e}")
        return None

def get_regions():
    ec2 = boto3.client("ec2")
    resp = ec2.describe_regions(AllRegions=True)
    return [r["RegionName"] for r in resp["Regions"] if r["OptInStatus"] in ("opt-in-not-required", "opted-in")]

def get_instances(region):
    ec2 = boto3.client("ec2", region_name=region)
    # Add pagination to handle large number of instances
    paginator = ec2.get_paginator('describe_instances')
    instances = []
    
    for page in paginator.paginate():
        for res in page["Reservations"]:
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
        return True
    except WaiterError as e:
        logger.error(f"Error waiting for instance to run: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error waiting for instance: {e}")
        return False

def get_instance_ips(region, instance_id):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        logger.info(f"Fetching IPs for instance {instance_id} in region {region}")
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        if not resp["Reservations"] or not resp["Reservations"][0]["Instances"]:
            logger.error(f"No instance found with ID {instance_id}")
            return None, None
        instance = resp["Reservations"][0]["Instances"][0]
        public_ip = instance.get("PublicIpAddress")
        private_ip = instance.get("PrivateIpAddress")
        logger.info(f"Found IPs: public={public_ip}, private={private_ip}")
        return public_ip, private_ip
    except ClientError as e:
        logger.error(f"AWS ClientError fetching IPs: {e}")
        return None, None
    except Exception as e:
        logger.error(f"Unexpected error fetching IPs: {e}")
        return None, None

def get_instance_state(region, instance_id):
    ec2 = boto3.client("ec2", region_name=region)
    try:
        logger.info(f"Getting state for instance {instance_id} in region {region}")
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        if not resp["Reservations"] or not resp["Reservations"][0]["Instances"]:
            logger.error(f"No instance found with ID {instance_id}")
            return None
        instance = resp["Reservations"][0]["Instances"][0]
        state = instance["State"]["Name"]
        logger.info(f"Instance state: {state}")
        return state
    except ClientError as e:
        logger.error(f"AWS ClientError getting instance state: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error getting instance state: {e}")
        return None

def lambda_handler(event, context):
    # Log the event for debugging
    logger.info(f"Received event: {json.dumps(event)}")
    
    # API Gateway V2 format paths are in rawPath
    path = event.get("rawPath", "")
    
    # API Gateway V2 method is in requestContext.http.method
    http_method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    
    # CORS headers for API Gateway V2
    headers = {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Content-Type": "application/json"
    }
    
    # Handle OPTIONS request (preflight CORS)
    if http_method == "OPTIONS":
        return {
            "statusCode": 200,
            "headers": headers,
            "body": ""
        }
    
    # Get Authorization header
    auth_header = event.get("headers", {}).get("authorization", "")
    
    # Skip token validation if jose module is not available
    if jwt_validation_available:
        # Validate token except for OPTIONS requests
        if not validate_cognito_token(auth_header) and http_method != "OPTIONS":
            logger.warning("Invalid token or missing authorization")
            return {
                "statusCode": 401,
                "headers": headers,
                "body": json.dumps({"error": "Unauthorized"})
            }
    
    params = event.get("queryStringParameters") or {}
    raw_body = event.get("body")
    is_base64 = event.get("isBase64Encoded", False)
    
    # Handle base64 encoded body (common in API Gateway V2)
    body = {}
    if raw_body:
        if is_base64:
            raw_body = base64.b64decode(raw_body).decode('utf-8')
        
        if isinstance(raw_body, str):
            try:
                body = json.loads(raw_body)
                logger.info(f"Parsed body: {json.dumps(body)}")
            except Exception as e:
                logger.error(f"Error parsing body: {e}")
                return {
                    "statusCode": 400,
                    "headers": headers,
                    "body": json.dumps({"error": f"Invalid JSON in request body: {str(e)}"})
                }
        elif isinstance(raw_body, dict):
            body = raw_body

    logger.info(f"Processing API Gateway V2 request: {http_method} {path}")
    
    try:
        if (path == "/verify-auth" or path == "/dev/verify-auth" or path == "/prod/verify-auth") and http_method == "GET":
            # Simple endpoint to check authentication status
            is_valid = validate_cognito_token(auth_header)
            user_info = get_user_info_from_token(auth_header) if is_valid else None
            
            return {
                "statusCode": 200,
                "headers": headers,
                "body": json.dumps({
                    "authenticated": is_valid,
                    "user": user_info
                })
            }
        elif path == "/dev/regions" or path == "/prod/regions":
            regions = get_regions()
            return {"statusCode": 200, "headers": headers, "body": json.dumps(regions)}
        elif path == "/dev/instances" or path == "/prod/instances":
            region = params.get("region")
            if not region:
                return {"statusCode": 400, "body": "Missing region"}
            instances = get_instances(region)
            return {"statusCode": 200, "headers": headers, "body": json.dumps(instances)}
        elif (path == "/start" or path == "/dev/start" or path == "/prod/start") and http_method == "POST":
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
        elif (path == "/stop" or path == "/dev/stop" or path == "/prod/stop") and http_method == "POST":
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
        elif (path == "/getip" or path == "/dev/getip" or path == "/prod/getip") and http_method == "POST":
            logger.info(f"Processing getip request with body: {json.dumps(body)}")
            
            # Validate required parameters
            region = body.get("region")
            if not region:
                logger.error("Missing region parameter")
                return {
                    "statusCode": 400, 
                    "headers": headers, 
                    "body": json.dumps({"error": "Missing region parameter"})
                }
                
            instance_id = body.get("instance_id")
            if not instance_id:
                logger.error("Missing instance_id parameter")
                return {
                    "statusCode": 400, 
                    "headers": headers, 
                    "body": json.dumps({"error": "Missing instance_id parameter"})
                }
            
            logger.info(f"Fetching IP information for {instance_id} in {region}")
            
            try:
                # First check if the instance exists and get its state
                state = get_instance_state(region, instance_id)
                if state is None:
                    return {
                        "statusCode": 404,
                        "headers": headers,
                        "body": json.dumps({"error": f"Instance {instance_id} not found in region {region}"})
                    }
                
                # Get the IP addresses
                public_ip, private_ip = get_instance_ips(region, instance_id)
                
                response_data = {
                    "public_ip": public_ip,
                    "private_ip": private_ip,
                    "state": state
                }
                
                logger.info(f"Successfully retrieved instance data: {json.dumps(response_data)}")
                
                return {
                    "statusCode": 200,
                    "headers": headers,
                    "body": json.dumps(response_data)
                }
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                error_msg = e.response.get('Error', {}).get('Message', str(e))
                logger.error(f"AWS ClientError in getip: {error_code} - {error_msg}")
                return {
                    "statusCode": 400,
                    "headers": headers,
                    "body": json.dumps({"error": f"AWS Error: {error_msg}"})
                }
            except Exception as e:
                logger.error(f"Error in getip: {str(e)}", exc_info=True)
                return {
                    "statusCode": 500,
                    "headers": headers,
                    "body": json.dumps({"error": f"Internal server error: {str(e)}"})
                }
        
        else:
            return {"statusCode": 404, "headers": headers, "body": json.dumps({"error": f"Not found: {path}"})}
    except Exception as e:
        logger.error(f"Unhandled error in lambda_handler: {str(e)}", exc_info=True)
        return {
            "statusCode": 500, 
            "headers": headers, 
            "body": json.dumps({"error": f"Internal server error: {str(e)}"})
        }

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

create s3 bucket with bucket policy and create objects index.html and callback.html

### 4. Create Cloudfront Distribution

Create Cloudfront Distribution with cloudfront-function.js in 'viewer-request' and origin as S3 (Set up proper bucket policy and integrate cloudfront)

### 5. Test it
