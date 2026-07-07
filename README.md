# Security360

A comprehensive multi-cloud security platform that provides automated infrastructure scanning, compliance monitoring, ML-powered threat detection, and Kubernetes security management across AWS, Azure, and GCP.

## What It Does

Security360 helps organizations maintain a strong cloud security posture by:

- **Cloud Security Scanning** — Automated checks across 30+ AWS services, Azure databases/VMs, and GCP resources to identify misconfigurations and vulnerabilities
- **Compliance Monitoring** — Continuous assessment against 20+ regulatory and industry frameworks with detailed reports
- **ML-Powered Threat Detection** — Anomaly detection on VPC Flow Logs and CloudTrail using ensemble machine learning (Isolation Forest, One-Class SVM, Autoencoder)
- **Kubernetes Security** — EKS/AKS/GKE cluster management, security tool installation (ArgoCD, Falco, Gatekeeper), and live log monitoring
- **AI Chatbot & Remediation** — AWS Bedrock-powered chatbot for security queries and automated remediation recommendations
- **Report Generation** — PDF, Word, and Excel reports for audits and stakeholder communication
- **Real-time Updates** — WebSocket-based scan progress and live Kubernetes tool logs

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Ant Design, TailwindCSS, Chart.js, Recharts, Framer Motion |
| Backend | Python, FastAPI, Uvicorn |
| Auth | AWS Cognito (signup, login, verification, password reset) |
| Cloud SDKs | boto3 (AWS), Azure SDK, GCP SDK |
| ML | scikit-learn, TensorFlow/Keras, pandas, NumPy |
| Database | AWS DynamoDB |
| Storage | AWS S3 (reports) |
| AI | AWS Lambda + Bedrock |
| Monitoring | Site24x7 integration |

## Services Offered

### Currently Available

#### Cloud Providers
- **AWS** — S3, EC2, IAM, RDS, EBS, VPC, Lambda, DynamoDB, EKS, ECR, ECS, GuardDuty, CloudTrail, CloudFront, SSM, Secrets Manager, SQS, SNS, OpenSearch, Redshift, ElastiCache, DocumentDB, NACL, Security Groups, KMS, Config, Inspector, SecurityHub, WAF, Backup
- **Azure** — Coming soon
- **GCP** — Coming soon

#### Compliance Frameworks (20+)
| Category | Frameworks |
|----------|-----------|
| Global | GDPR, PCI DSS, HIPAA, SOC 2, FedRAMP, NIST CSF, NIST 800-53, ISO 27001, ISO 27018, ISO 42001 |
| India-specific | DPDP Act, RBI CSF, SEBI CSCRF, NDHM, EHR Standards |
| Cloud-native | AWS Well-Architected (AWAF), Azure WAF, GCP CAF |
| Security | CIS Benchmark, OWASP Top 10 |

#### Industry Dashboards
- Healthcare
- Finance / Banking
- SaaS
- Government
- E-commerce

#### ML Threat Detection
- VPC Flow Logs anomaly detection (ensemble majority vote)
- CloudTrail suspicious activity detection (TF-IDF + keyword flagging)
- AI-enriched findings via AWS Bedrock

#### Kubernetes Security
- Multi-cloud cluster listing (EKS, AKS, GKE)
- Security tool lifecycle management (install, debug, remove)
- Live log streaming via WebSocket
- Security report generation (PDF)

### Planned / Future

- Azure cloud security scanning (VMs, databases, networking, Key Vault)
- GCP cloud security scanning (Compute, Storage, IAM, BigQuery)
- Custom compliance framework builder
- Scheduled automated scans with alerting
- Multi-tenancy and organization-level dashboards
- SBOM (Software Bill of Materials) analysis

## How to Run

### Prerequisites

- Python 3.10+
- Node.js 18+
- AWS account with configured credentials
- AWS Cognito User Pool (for authentication)
- DynamoDB tables set up
- S3 bucket for report storage

### Backend Setup

The backend runs in a Python virtual environment.

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Create a `.env` file in the `backend/` directory with the required environment variables:

```env
BOTO3_REGION=your-aws-region
USER_POOL_ID=your-cognito-user-pool-id
CLIENT_ID=your-cognito-client-id
CLIENT_SECRET=your-cognito-client-secret
DYNAMODB_TABLE=your-dynamodb-table
S3_BUCKET=your-s3-bucket-name
```

Start the backend server:

```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm run start
```

The frontend runs on `http://localhost:3000` and proxies API requests to the backend at `http://localhost:8000`.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `BOTO3_REGION` | AWS region for SDK calls |
| `USER_POOL_ID` | Cognito User Pool ID |
| `CLIENT_ID` | Cognito App Client ID |
| `CLIENT_SECRET` | Cognito App Client Secret |
| `DYNAMODB_TABLE` | DynamoDB table for user data |
| `S3_BUCKET` | S3 bucket for storing scan reports |

## Project Structure

```
Security360/
├── backend/
│   ├── Auth/              # Authentication (Cognito)
│   ├── azure/             # Azure security checks
│   ├── config/            # Account configurations
│   ├── db/                # DynamoDB CRUD operations
│   ├── Excel_Report_Generator/
│   ├── ML/                # Machine learning models
│   │   ├── Cloudtrail/    # CloudTrail anomaly detection
│   │   └── VpcFlowLogs/   # VPC Flow Logs anomaly detection
│   ├── Model/             # Pydantic models
│   ├── modules/           # Security check modules
│   │   ├── AWAF/          # AWS Well-Architected Framework
│   │   ├── CIS/           # CIS Benchmarks
│   │   ├── frameworks/    # Compliance frameworks (DPDP, RBI, SEBI, etc.)
│   │   ├── ISO/           # ISO standards
│   │   ├── kubernetes/    # K8s security management
│   │   ├── Website/       # OWASP web security
│   │   └── ...
│   ├── utils/             # Utilities (S3 upload, scanning, chatbot, etc.)
│   ├── word_report_generator/
│   ├── main.py            # FastAPI application entry point
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/    # React components
│   │   │   ├── Auth/      # Login, Signup, Verification
│   │   │   ├── Compliance/# Compliance dashboards
│   │   │   ├── Industry/  # Industry-specific views
│   │   │   ├── pages/     # Cloud-specific pages (AWS, Azure, GCP)
│   │   │   └── ...
│   │   └── utils/         # Helpers, configs
│   └── package.json
└── README.md
```

## License

Proprietary — All rights reserved.
