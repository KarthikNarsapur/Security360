from pydantic import BaseModel
from typing import List, Optional, Dict


class AccountDetail(BaseModel):
    account_id: str
    role_arn: str
    account_name: Optional[str] = ""


class VpcFlowLogSource(BaseModel):
    """Represents a single VPC Flow Log source with its destination details."""
    flowLogId: str
    destinationType: str  # "cloud-watch-logs", "s3", "kinesis-data-firehose"
    logGroupName: Optional[str] = None  # For CloudWatch
    s3Bucket: Optional[str] = None  # For S3
    s3Prefix: Optional[str] = None  # For S3
    firehoseArn: Optional[str] = None  # For Firehose


class AccessTokenModel(BaseModel):
    access_token: Optional[str] = None
    username: str
    accounts: List[AccountDetail]
    regions: list[str]
    pillars: Optional[list[str]] = None
    vpcFlowLogNames: Optional[Dict[str, Dict[str, str]]] = None
    # New field: selected VPC flow log sources with destination type info
    vpcFlowLogSources: Optional[Dict[str, Dict[str, VpcFlowLogSource]]] = None


class ReportRequest(BaseModel):
    account_id: str
    username: str
    type: str
    is_sample: bool
    threat_detection_scan_type: Optional[List[str]] = None


class UserQueryModel(BaseModel):
    query: str


class DateRangeModel(BaseModel):
    # start_date: str
    # end_date: str
    account_id: str
    username: str
    regions: list[str]


class CISRuleScanModel(BaseModel):
    account_details: List[AccountDetail]
    regions: List[str]


class ListEKSClusterModel(BaseModel):
    regions: List[str]
    username: str
    accounts: List[AccountDetail]


class RunScriptRequest(BaseModel):
    region: str
    cluster_name: str
    username: str
    tool: str
    action: str
    ws_id: str


class UserNameModel(BaseModel):
    username: str


class PDFReportModel(BaseModel):
    username: str
    account: str
    cluster: str
    report_type: str
    date: str
    pdf_name: str


class ContactFormModel(BaseModel):
    name: str
    email: str
    phone: str
    interest: str = ""
    company: str = ""
    message: str = ""
    consent: bool


class WebsiteScanModel(BaseModel):
    username: str
    websites: list[str]
    framework: str = "owasp"
