# Lambda: Check for Publicly Accessible Functions and Unencrypted Environment Variables

def check_lambda_compliance(session):
    lambda_client = session.client('lambda')
    functions = lambda_client.list_functions()['Functions']
    results = {
        "functions_with_env_variables": [],
        "functions_with_public_access": []
    }

    for func in functions:
        func_name = func['FunctionName']
        config = lambda_client.get_function_configuration(FunctionName=func_name)

        # Check if environment variables exist
        if config.get('Environment', {}).get('Variables'):
            results["functions_with_env_variables"].append(func_name)

        # Check if Lambda is attached to a public-facing URL (e.g., via URL config)
        try:
            url_config = lambda_client.get_function_url_config(FunctionName=func_name)
            if url_config.get('AuthType') == 'NONE':
                results["functions_with_public_access"].append(func_name)
        except lambda_client.exceptions.ResourceNotFoundException:
            pass

    return results
