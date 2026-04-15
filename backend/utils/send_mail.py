import os
from Model.model import ContactFormModel
from botocore.exceptions import ClientError

from utils.upload_to_s3 import save_contact_us_to_s3
import boto3

from utils.exceptions import handle_error


def generate_contact_email_html(data: ContactFormModel):
    """Generate HTML content for Security360 contact form email."""
    logo_url = os.getenv("CLOUDTHAT_LOGO_S3")
    html_content = f"""
    <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f6f8;
                    color: #333333;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    width: 100%;
                    max-width: 600px;
                    margin: 20px auto;
                    background-color: #ffffff;
                    border-radius: 10px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                    overflow: hidden;
                    padding: 20px;
                }}
                .header {{
                    text-align: center;
                    padding-bottom: 20px;
                    border-bottom: 1px solid #e0e0e0;
                }}
                .header img {{
                    max-width: 120px;
                    margin-bottom: 10px;
                }}
                h2 {{
                    color: #1a202c;
                    margin-bottom: 10px;
                }}
                p {{
                    color: #555555;
                    line-height: 1.5;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }}
                th, td {{
                    text-align: left;
                    padding: 10px;
                    border: 1px solid #e0e0e0;
                }}
                th {{
                    background-color: #f0f4f8;
                }}
                .footer {{
                    margin-top: 20px;
                    font-size: 0.9rem;
                    color: #777777;
                    text-align: center;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <img src="{logo_url}" alt="Security360 Logo" width="120" />
                    <h2>Security360 Contact Form Submission</h2>
                </div>
                <p>You have received a new message from your website contact form. Please review the details below and contact the user .</p>
                <table>
                    <tr><th>Name</th><td>{data.name}</td></tr>
                    <tr><th>Email</th><td>{data.email}</td></tr>
                    <tr><th>Phone</th><td>{data.phone}</td></tr>
                    <tr><th>Interest</th><td>{data.interest}</td></tr>
                    <tr><th>Company</th><td>{data.company or '-'}</td></tr>
                    <tr><th>Consent</th><td>{'Yes' if data.consent else 'No'}</td></tr>
                    <tr><th>Message</th><td>{data.message or '-'}</td></tr>
                </table>
                <p>Thank you for using <strong>Security360</strong>.</p>
                <div class="footer">
                    &copy; 2025 Security360. All rights reserved.
                </div>
            </div>
        </body>
    </html>
    """
    return html_content


def send_mail_function(request: ContactFormModel):
    try:
        # Save contact us form data to S3
        save_contact_us_to_s3(request)

        # Get emails from environment
        sender_email = os.getenv("SENDER_EMAIL")
        target_emails = os.getenv("TARGET_EMAIL", "").split(",")
        target_emails = [email.strip() for email in target_emails if email.strip()]
        print("sender_email: ", sender_email)
        print("target emails: ", target_emails)

        if not all([sender_email, target_emails]):
            return {
                "status": "error",
                "message": "Email configuration missing in environment",
            }

        # generate html content
        html_content = generate_contact_email_html(request)

        # Create SES client (Boto3 automatically uses EC2 role credentials)
        ses_client = boto3.client("ses")

        # Send email
        response = ses_client.send_email(
            Source=sender_email,
            Destination={"ToAddresses": target_emails},
            Message={
                "Subject": {"Data": f"New Contact Form Submission from {request.name}"},
                "Body": {"Html": {"Data": html_content}},
            },
        )

        return {"status": "ok", "message": "Email sent successfully via SES"}

    except ClientError as e:
        print(f"SES error: {e.response['Error']['Message']}")
        error_code = e.response["Error"]["Code"]
        error_message = handle_error(error_code)
        return {"status": "error", "error_message": error_message}
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return {"status": "error", "message": "Failed to send email"}
