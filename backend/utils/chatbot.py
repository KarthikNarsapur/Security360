import json
import requests
import os
from botocore.exceptions import ClientError

from utils.exceptions import handle_error

from Model.model import UserQueryModel


def get_chatbot(user_query: UserQueryModel):

    try:
        function_url = os.getenv("FUNCTION_URL")
        # print(user_query.query)
        response = requests.post(
            function_url,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"query": user_query.query, "logs_type": "chatbot"}),
        )

        result = response.json()
        # print(result)
        return {"status": "ok", "chatbot_response": result["chatbot"]}
    except ClientError as e:
        print(f"error: {str(e)}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Error: {str(e)}")
        return {"status": "error", "error_message": str(e)}
