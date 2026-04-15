def handle_error(error_code, raw_message=None):
    error_messages = {
        # Auth
        "ResourceNotFoundException": "The requested resource was not found.",
        "InvalidParameterException": "One or more parameters provided are invalid.",
        "InvalidPasswordException": "Password does not meet security requirements.",
        "UsernameExistsException": "This username already exists.",
        "TooManyRequestsException": "Too many requests. Please wait and try again.",
        "InternalErrorException": "An internal error occurred. Please try later.",
        "TooManyFailedAttemptsException": "Too many failed attempts. Try again later.",
        "CodeMismatchException": "The confirmation code is incorrect.",
        "ExpiredCodeException": "The confirmation code has expired.",
        "LimitExceededException": "Limit exceeded. Try again later.",
        "UserNotFoundException": "User does not exist.",
        "CodeDeliveryFailureException": "Unable to deliver confirmation code. Try again.",
        "UserNotConfirmedException": "User has not been confirmed.",
        "PasswordResetRequiredException": "User must reset password before continuing.",
        "NotAuthorizedException": "Incorrect username or password.",
        # db
        "ConditionalCheckFailedException": "User already exists.",
        "ProvisionedThroughputExceededException": "Provisioned throughput for the table was exceeded. Try again later.",
        "ResourceNotFoundException": "The requested resource could not be found. Verify the table or resource exists.",
        "ItemCollectionSizeLimitExceededException": "The item size exceeds the allowed limit for the collection.",
        "TransactionConflictException": "There was a conflict with the transaction. Try again.",
        "RequestLimitExceeded": "Request limit exceeded. Please try again later.",
        "InternalServerError": "Internal server error occurred. Please try again later.",
        "ReplicatedWriteConflictException": "Write conflict detected in replicated writes. Please try again.",
        # SES
        "MessageRejected": "The email was rejected by SES. Check content, recipient, or sending limits.",
        "MailFromDomainNotVerifiedException": "The sender domain is not verified in SES.",
        "ConfigurationSetDoesNotExistException": "The SES configuration set does not exist.",
        "ConfigurationSetSendingPausedException": "Sending is paused for the SES configuration set.",
        "AccountSendingPausedException": "Your SES account sending is paused. Contact AWS support.",
    }
    
    if raw_message:
        # Special handling for InvalidParameterException with known patterns
        if error_code == "InvalidParameterException":
            if "no registered/verified email or phone_number" in raw_message:
                return "User does not have a verified email or phone number."
            elif "missing required parameter" in raw_message.lower():
                return "Required parameter missing in request."
            else:
                return "One or more parameters provided are invalid."

        # For other errors, prefer dictionary but fallback to raw message
        return error_messages.get(error_code, raw_message)
    
    return error_messages.get(error_code, "An unknown error occurred.")
