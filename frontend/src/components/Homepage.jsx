import { useEffect, useState } from "react";
import { Button } from "antd";
import RoleCreation from "./RoleCreation";
import AzureRoleCreation from "./AzureRoleCreation";
import { fetchUserDetails } from "./Utils";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Search,
  Brain,
  FileCheck,
  BarChart3,
  Globe,
  Cloud,
  Server,
  Lock,
  Plus,
} from "lucide-react";
import { FaAws } from "react-icons/fa";
import { VscAzure } from "react-icons/vsc";
import { BiLogoGoogleCloud } from "react-icons/bi";

function HomePage({
  userName,
  fullName,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) {
  const [showAwsRoleCreation, setShowAwsRoleCreation] = useState(false);
  const [showAzureRoleCreation, setShowAzureRoleCreation] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const getUserData = async () => {
      const result = await fetchUserDetails({ navigate });
      if (result.status === "ok") {
        setUserName(result.userName);
        setFullName(result.fullName);
        setAccountDetails(result.accountDetails);
        setEksAccountDetails(result.eksAccountDetails);
      }
    };
    getUserData();
  }, []);

  const Section = ({ title, children }) => (
    <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 mb-6">
      <h2 className="text-2xl font-bold text-indigo-900 dark:text-gray-200 mb-4">
        {title}
      </h2>
      {children}
    </div>
  );

  const Feature = ({ icon, title, desc }) => (
    <div className="flex items-start gap-3">
      <div className="mt-1 p-2 rounded-lg bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 flex-shrink-0">
        {icon}
      </div>
      <div>
        <h4 className="font-semibold text-slate-800 dark:text-white text-sm">{title}</h4>
        <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">{desc}</p>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="pl-12 p-6">
        <div className="max-w-7xl mx-auto">

          {/* ── Welcome Banner ──────────────────────────────────────────── */}
          <div className="mb-8">
            <div className="flex items-center justify-between bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700">
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-indigo-700 bg-clip-text text-transparent">
                  Welcome to Security360{fullName ? `, ${fullName}` : ""}
                </h1>
                <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
                  Your unified cloud security posture management platform
                </p>
              </div>
            </div>
          </div>

          {/* ── What is Security360 ─────────────────────────────────────── */}
          <Section title="What is Security360?">
            <p className="text-slate-700 dark:text-slate-300 leading-relaxed mb-4">
              Security360 is a comprehensive cloud security posture management (CSPM) platform designed to help organizations identify vulnerabilities, misconfigurations, and compliance gaps across their entire cloud infrastructure. Whether you are running workloads on Amazon Web Services, Microsoft Azure, or Google Cloud Platform, Security360 provides a single unified dashboard to monitor, assess, and improve your security posture across all three major cloud providers simultaneously.
            </p>
            <p className="text-slate-700 dark:text-slate-300 leading-relaxed">
              The platform goes beyond simple configuration checks. It combines infrastructure scanning, machine learning-powered threat detection, compliance framework assessments, and industry-specific security recommendations into one cohesive experience. Instead of juggling multiple tools for different clouds and different compliance requirements, Security360 brings everything together so your security team can focus on what matters most — fixing vulnerabilities and reducing risk.
            </p>
          </Section>

          {/* ── Core Capabilities ───────────────────────────────────────── */}
          <Section title="Core Capabilities">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <Feature
                icon={<Search className="w-5 h-5" />}
                title="Infrastructure Security Scanning"
                desc="Automatically scans your cloud accounts for security misconfigurations including open security groups, public S3 buckets, unencrypted databases, missing MFA, overly permissive IAM policies, and dozens of other common vulnerabilities. Scans run per-region and cover both regional and global services."
              />
              <Feature
                icon={<Brain className="w-5 h-5" />}
                title="ML-Powered Threat Detection"
                desc="Uses an ensemble of three machine learning models — Isolation Forest, One-Class SVM, and Autoencoder — to analyze CloudTrail logs and VPC Flow Logs for anomalous behavior. The system flags suspicious API calls, unusual network traffic patterns, privilege escalation attempts, and potential data exfiltration activities."
              />
              <Feature
                icon={<FileCheck className="w-5 h-5" />}
                title="Compliance Framework Assessments"
                desc="Evaluate your cloud infrastructure against major compliance frameworks including GDPR, PCI DSS, HIPAA, SOC 2, FedRAMP, NIST CSF, CIS Benchmarks, ISO 27001, and India-specific frameworks like DPDP Act, RBI CSF, SEBI CSCRF, NDHM, and EHR Standards. Each assessment maps your cloud resources to specific compliance controls."
              />
              <Feature
                icon={<BarChart3 className="w-5 h-5" />}
                title="Industry-Based Recommendations"
                desc="Not sure which compliance frameworks apply to your business? Security360 provides industry-specific guidance for Healthcare, Finance, SaaS, Government, and E-commerce sectors. Each industry profile identifies mandatory, recommended, and optional frameworks so you can prioritize what matters most for your business."
              />
              <Feature
                icon={<Globe className="w-5 h-5" />}
                title="Multi-Cloud Unified View"
                desc="Compliance and industry dashboards aggregate findings from AWS, Azure, and GCP into a single view with cloud filter controls. See all your GDPR-relevant findings across every cloud provider in one table, filter by cloud, sort by severity, and export reports — no switching between consoles."
              />
              <Feature
                icon={<Shield className="w-5 h-5" />}
                title="Security Service Monitoring"
                desc="Monitors whether critical security services are enabled across your accounts — GuardDuty, AWS Config, Inspector, Security Hub, CloudTrail, WAF, and IAM Access Analyzer. Provides immediate visibility into gaps in your security tooling coverage."
              />
            </div>
          </Section>

          {/* ── How It Works ────────────────────────────────────────────── */}
          <Section title="How It Works">
            <div className="space-y-4 text-slate-700 dark:text-slate-300 leading-relaxed">
              <p>
                Security360 uses a secure cross-account access model. For AWS, you create an IAM Role in your account with read-only permissions, and Security360 assumes that role to perform scans without storing your credentials. For Azure, you register a service principal with Reader access to your subscriptions. For GCP, you provide a service account with Viewer permissions on your projects.
              </p>
              <p>
                Once connected, you can run on-demand scans from the cloud-specific dashboards (AWS, Azure, or GCP sections in the sidebar). Scan results are stored securely and can be viewed anytime from the Summary and Findings pages. The compliance and industry dashboards then pull these results and map them against the relevant framework controls, giving you a cross-cloud compliance posture view.
              </p>
              <p>
                For threat detection, Security360 ingests CloudTrail audit logs and VPC Flow Logs, applies feature engineering (TF-IDF vectorization, keyword flagging for suspicious terms like "delete", "terminate", "escalate", "unauthorized"), and runs three independent anomaly detection models. A finding is flagged only when at least two of the three models agree, reducing false positives significantly. The flagged anomalies are then analyzed by an AI service to generate human-readable security findings with context and remediation guidance.
              </p>
              <p>
                Reports can be exported as JSON, CSV, or Excel formats. The platform also supports Kubernetes security scanning for EKS clusters, website security scanning against OWASP Top 10, and integration with Site24x7 for infrastructure monitoring dashboards.
              </p>
            </div>
          </Section>

          {/* ── Supported Clouds ────────────────────────────────────────── */}
          <Section title="Supported Cloud Providers">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="flex items-center gap-3 p-4 rounded-xl bg-orange-50 dark:bg-orange-900/10 border border-orange-200 dark:border-orange-800">
                <FaAws className="w-8 h-8 text-orange-600" />
                <div>
                  <h4 className="font-semibold text-slate-800 dark:text-white">Amazon Web Services</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400">EC2, S3, RDS, IAM, VPC, GuardDuty, CloudTrail, and more</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-4 rounded-xl bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800">
                <VscAzure className="w-8 h-8 text-blue-600" />
                <div>
                  <h4 className="font-semibold text-slate-800 dark:text-white">Microsoft Azure</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400">VMs, Storage, SQL, Key Vault, NSGs, and more</p>
                </div>
              </div>
              <div className="flex items-center gap-3 p-4 rounded-xl bg-emerald-50 dark:bg-emerald-900/10 border border-emerald-200 dark:border-emerald-800">
                <BiLogoGoogleCloud className="w-8 h-8 text-emerald-600" />
                <div>
                  <h4 className="font-semibold text-slate-800 dark:text-white">Google Cloud Platform</h4>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Compute Engine, Cloud Storage, Cloud SQL, BigQuery, and more</p>
                </div>
              </div>
            </div>
          </Section>

          {/* ── Connect Your Accounts ───────────────────────────────────── */}
          <Section title="Connect Your Cloud Accounts">
            <p className="text-slate-700 dark:text-slate-300 leading-relaxed mb-6">
              To start scanning, connect your cloud accounts below. Security360 uses read-only access — it never modifies your infrastructure. You can add multiple accounts from each cloud provider.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-5 rounded-xl border-2 border-dashed border-orange-300 dark:border-orange-700 hover:border-orange-500 transition-colors">
                <div className="flex items-center gap-3 mb-3">
                  <FaAws className="w-6 h-6 text-orange-600" />
                  <h4 className="font-semibold text-slate-800 dark:text-white">AWS Account</h4>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
                  Create an IAM Role with SecurityAudit policy and provide the Role ARN.
                </p>
                <Button
                  icon={<Plus className="w-4 h-4" />}
                  onClick={() => setShowAwsRoleCreation(true)}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:!from-indigo-700 hover:!to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-4 py-1.5 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 w-full"
                >
                  Add AWS Account
                </Button>
              </div>
              <div className="p-5 rounded-xl border-2 border-dashed border-blue-300 dark:border-blue-700 hover:border-blue-500 transition-colors">
                <div className="flex items-center gap-3 mb-3">
                  <VscAzure className="w-6 h-6 text-blue-600" />
                  <h4 className="font-semibold text-slate-800 dark:text-white">Azure Subscription</h4>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
                  Register a service principal with Reader access and provide credentials.
                </p>
                <Button
                  icon={<Plus className="w-4 h-4" />}
                  onClick={() => setShowAzureRoleCreation(true)}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:!from-indigo-700 hover:!to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-4 py-1.5 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 w-full"
                >
                  Add Azure Subscription
                </Button>
              </div>
              <div className="p-5 rounded-xl border-2 border-dashed border-emerald-300 dark:border-emerald-700 hover:border-emerald-500 transition-colors">
                <div className="flex items-center gap-3 mb-3">
                  <BiLogoGoogleCloud className="w-6 h-6 text-emerald-600" />
                  <h4 className="font-semibold text-slate-800 dark:text-white">GCP Project</h4>
                </div>
                <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">
                  Create a service account with Viewer role and provide the project credentials.
                </p>
                <Button
                  icon={<Plus className="w-4 h-4" />}
                  onClick={() => setShowAwsRoleCreation(true)}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:!from-indigo-700 hover:!to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-4 py-1.5 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 w-full"
                >
                  Add GCP Project
                </Button>
              </div>
            </div>
          </Section>

          {/* ── Modals ──────────────────────────────────────────────────── */}
          {showAwsRoleCreation && (
            <RoleCreation onClose={() => setShowAwsRoleCreation(false)} />
          )}
          {showAzureRoleCreation && (
            <AzureRoleCreation onClose={() => setShowAzureRoleCreation(false)} />
          )}
        </div>
      </div>
    </div>
  );
}

export default HomePage;
