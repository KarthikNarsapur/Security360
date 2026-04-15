import boto3
import subprocess
import os
from Model.model import RunScriptRequest
import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from datetime import datetime, timezone, timedelta

kubeconfig_path = os.path.expanduser("~/.kube/config")

active_connections = []

tool_action_map = {
    "listnamespace": ["setup"],
    "argocd": ["setup", "debug", "remove"],
    "falco": ["setup", "debug", "remove"],
    "gatekeeper": ["setup", "debug", "remove"],
    "kured": ["setup", "debug", "remove"],
    "headlamp": ["setup", "debug", "remove"],
    "kubescape": ["scan"],
    "kubehunter": ["scan"],
}


async def kubernetes_websocket_manager(websocket: WebSocket, ws_id: str):
    await websocket.accept()
    # active_connections.append(websocket)
    active_connections.append({"websocket": websocket, "id": ws_id})

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections[:] = [
            conn for conn in active_connections if conn["websocket"] != websocket
        ]


async def close_websocket(ws_id: str, reason: str = ""):
    disconnected = []
    for conn in active_connections:
        if conn["id"] == ws_id:
            try:
                if reason:
                    await conn["websocket"].send_json({"message": reason})
                await conn["websocket"].close()
            except:
                disconnected.append(conn)
    for conn in disconnected:
        active_connections.remove(conn)
    active_connections[:] = [conn for conn in active_connections if conn["id"] != ws_id]


async def send_setup_logs(message: str = "", ws_id: str = ""):
    data = {"message": message}
    disconnected = []
    for conn in active_connections:
        if conn["id"] == ws_id:
            print(f"sending data: {data} with id {ws_id}")
            try:
                await conn["websocket"].send_json(data)
            except:
                disconnected.append(conn)

    for conn in disconnected:
        active_connections.remove(conn)


async def kubernetes_tool_setup_function(data: RunScriptRequest):

    from db.crud import increament_scan_count, check_scan_threshold

    REGION = data.region
    BOTO3_REGION = os.getenv("BOTO3_REGION")

    # Step 1 Get file name
    if data.tool not in tool_action_map:
        return {"error": f"Tool '{data.tool}' is not allowed."}

    if data.action not in tool_action_map[data.tool]:
        return {
            "error": f"Action '{data.action}' is not allowed for tool '{data.tool}'."
        }

    threshold_response = check_scan_threshold(
        username=data.username, scan_type=data.tool
    )
    if threshold_response.get("status") == "error":
        return threshold_response

    file_name = ""
    if data.tool == "listnamespace":
        file_name = "list_namespace.sh"
    elif data.tool in ["argocd"]:
        if data.action == "setup" or data.action == "debug":
            file_name = f"install-{data.tool}.sh"
        elif data.action == "remove":
            file_name = f"remove-{data.tool}.sh"
    elif data.tool in ["gatekeeper", "falco", "kured", "headlamp"]:
        if data.action == "setup" or data.action == "debug":
            file_name = f"deploy-{data.tool}.sh"
        elif data.action == "remove":
            file_name = f"remove-{data.tool}.sh"
    elif data.tool in ["kubescape", "kubehunter"]:
        if data.action == "scan":
            file_name = f"scan-{data.tool}.sh"
    script_path = f"../Kubernetes_Scripts/{file_name}"

    if not os.path.exists(script_path):
        print("script not found at: ", script_path)
        return {"status": "error", "message": f"Script not found at: "}

    # Step 2: Get userdata from DynamoDB
    dynamodb_client = boto3.resource("dynamodb", region_name=BOTO3_REGION)
    table_name = os.getenv("USERDATA_TABLE_DYNAMODB")
    table = dynamodb_client.Table(table_name)

    existing_data = table.get_item(Key={"UserName": data.username})
    user_data = existing_data.get("Item", {})
    roles_info = user_data.get("Kubernetes_Roles_Info", [])[0]
    print("roles info: ", roles_info)
    account_id = roles_info["account_id"]
    role_arn = roles_info["role_arn"]

    # Step 3: Assume Role to get temporary credentials
    sts_client = boto3.client("sts", region_name=BOTO3_REGION)
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn, RoleSessionName="SecurityAuditSession"
        )
    except Exception as e:
        print(f"Error assuming role for {account_id}: {str(e)}")
        await close_websocket(
            ws_id=data.ws_id, reason="Error occurred, closing connection"
        )
        return
    credentials = assumed_role["Credentials"]
    access_key = credentials["AccessKeyId"]
    secret_key = credentials["SecretAccessKey"]
    session_token = credentials["SessionToken"]

    # Step 4: Create a new session using the assumed role credentials
    session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=REGION,
    )

    try:
        # Step 5: Run the connect-eks.sh script to set up the kubeconfig context
        connect_eks_script_path = "../Kubernetes_Scripts/connect-eks.sh"
        if not os.path.exists(connect_eks_script_path):
            print(f"connect eks script not found at: {connect_eks_script_path}")
            await close_websocket(
                ws_id=data.ws_id, reason="Error occurred, closing connection"
            )
            return {
                "status": "error",
                "message": "Shell script not found",
            }

        # Execute the script with the required arguments
        result = subprocess.run(
            ["bash", connect_eks_script_path, account_id, REGION, data.cluster_name],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            await close_websocket(
                ws_id=data.ws_id, reason="Error occurred, closing connection"
            )
            return {
                "status": "error",
                "message": f"Script failed: {result.stderr.strip()}",
            }
        print("EKS context updated successfully, now running script...")

        # Step 6: Run the script
        process = subprocess.Popen(
            ["bash", script_path, data.username, account_id, REGION, data.cluster_name],
            env={**os.environ, "KUBECONFIG": kubeconfig_path},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        output_lines = []

        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                output_lines.append(line)
                await send_setup_logs(line.strip(), ws_id=data.ws_id)
                await asyncio.sleep(0.1)

        if process.returncode != 0:
            await close_websocket(
                ws_id=data.ws_id, reason="Error occurred, closing connection"
            )
            return {
                "status": "error",
                "message": f"Script failed: {result.stderr.strip()}",
            }

        await send_setup_logs("setup completed", ws_id=data.ws_id)
        await close_websocket(ws_id=data.ws_id, reason="Setup completed")
        return {
            "status": "ok",
            "message": "script executed successfully",
        }

    except Exception as e:
        print("Error while running script: ", str(e))
        await close_websocket(
            ws_id=data.ws_id, reason="Error occurred, closing connection"
        )
        return {
            "status": "error",
            "message": str(e),
        }
