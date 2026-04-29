import { useState } from "react";
import { Button, Input, Form } from "antd";
import { X, Download, ArrowRight, ArrowLeft, FileText } from "lucide-react";
import Cookies from "js-cookie";
import { useNavigate } from "react-router-dom";
import { notifyError, notifySuccess, notifyInfo } from "./Notification";
import Spinner from "./UI/Spinner";
import { GetNote } from "./Utils";

export default function AzureRoleCreation({ onClose }) {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(1);
  const [downloading, setDownloading] = useState(false);
  const navigate = useNavigate();
  const backendUrl = process.env.REACT_APP_BACKEND_URL;

  const handleDownloadSOP = async () => {
    setDownloading(true);
    try {
      const res = await fetch(`${backendUrl}/api/sop/azure-service-principal`);
      const data = await res.json();
      if (data.status === "ok" && data.url) {
        window.open(data.url, "_blank");
      } else {
        notifyError(data.error_message || "Failed to get download link");
      }
    } catch (err) {
      console.error("SOP download error:", err);
      notifyError("Failed to download SOP document");
    } finally {
      setDownloading(false);
    }
  };

  const handleSubmit = async () => {
    const values = await form.validateFields();
    const access_token = Cookies.get("access_token");

    const payload = {
      roles: [
        {
          account_id: values.subscription_id,
          role_arn: values.subscription_id,
          account_name: values.subscription_name || "",
          tenant_id: values.tenant_id,
          client_id: values.client_id,
          client_secret: values.client_secret,
        },
      ],
      access_token: access_token,
      role_type: "azure",
    };

    if (!payload.roles[0].account_id) {
      notifyError("Missing required fields!");
      return;
    }
    if (!payload.access_token) {
      notifyInfo("Session expired. Please login again.");
      navigate("/login");
      return;
    }

    try {
      setLoading(true);
      const response = await fetch(`${backendUrl}/api/saveroleinfo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      if (result.status === "ok") {
        notifySuccess("Azure Subscription Saved Successfully");
        const existing =
          JSON.parse(localStorage.getItem("azure_account_details") || "[]") || [];
        const updated = [...existing, payload.roles[0]];
        localStorage.setItem("azure_account_details", JSON.stringify(updated));
        onClose();
      } else {
        notifyError(result.error_message || "Failed to save subscription");
      }
    } catch (err) {
      console.error("Error:", err);
      notifyError("Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-40 z-50 flex items-center justify-center">
      <div className="bg-white w-2/3 max-h-[90vh] overflow-y-auto p-6 relative bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg rounded-2xl shadow-2xl shadow-slate-900/20 border border-slate-200 dark:border-slate-700">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-lg p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
        >
          <X className="w-5 h-5 text-slate-600 dark:text-slate-400" />
        </button>

        <h3 className="text-2xl font-bold mb-4 bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
          Add Azure Subscription
        </h3>

        {/* Step indicator */}
        <div className="flex items-center gap-3 mb-6">
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${step === 1 ? "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300" : "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"}`}>
            <span className="w-5 h-5 rounded-full bg-current/20 flex items-center justify-center text-xs">1</span>
            Setup Guide
          </div>
          <ArrowRight className="w-4 h-4 text-slate-400" />
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-full text-sm font-medium transition-colors ${step === 2 ? "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300" : "bg-slate-100 text-slate-500 dark:bg-slate-800 dark:text-slate-400"}`}>
            <span className="w-5 h-5 rounded-full bg-current/20 flex items-center justify-center text-xs">2</span>
            Enter Credentials
          </div>
        </div>

        {step === 1 && (
          <div>
            <div className="bg-slate-50/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-xl border border-slate-200 dark:border-slate-700 p-6 shadow-xl shadow-indigo-500/10">
              <div className="flex items-start gap-4 mb-6">
                <div className="p-3 bg-blue-100 dark:bg-blue-900/40 rounded-xl">
                  <FileText className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                </div>
                <div>
                  <h4 className="text-lg font-semibold text-slate-800 dark:text-white mb-1">
                    Before you begin
                  </h4>
                  <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                    You'll need to create a Service Principal in Azure with <span className="font-medium text-slate-800 dark:text-slate-200">Reader</span> access 
                    to your subscription. This allows Security360 to scan your resources in read-only mode.
                  </p>
                </div>
              </div>

              <div className="space-y-3 mb-6">
                <p className="text-sm text-slate-600 dark:text-slate-400 leading-relaxed">
                  Download the PDF below and follow the step-by-step instructions to create a Service Principal. 
                  The download link will expire in <span className="font-semibold text-amber-600 dark:text-amber-400">60 minutes</span>.
                </p>
              </div>

              <Button
                icon={<Download className="w-4 h-4" />}
                onClick={handleDownloadSOP}
                loading={downloading}
                className="!bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-5 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              >
                Download detailed step-by-step instructions (PDF)
              </Button>

              <div className="mt-6 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-700/50 rounded-lg p-4">
                <h5 className="text-sm font-semibold text-amber-800 dark:text-amber-300 mb-2">Note: Field Mapping</h5>
                <ul className="text-sm text-amber-700 dark:text-amber-400 space-y-1 list-disc list-inside">
                  <li><span className="font-mono font-medium">appId</span> in Azure CLI output = <span className="font-semibold">Client ID</span> in the form</li>
                  <li><span className="font-mono font-medium">password</span> in Azure CLI output = <span className="font-semibold">Client Secret</span> in the form</li>
                </ul>
              </div>
            </div>

            <div className="mt-6 flex justify-end">
              <Button
                icon={<ArrowRight className="w-4 h-4" />}
                onClick={() => setStep(2)}
                className="!bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              >
                I've created the Service Principal — Continue
              </Button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div>
            <div>
              <GetNote note="Enter your Azure Service Principal credentials. These are used to authenticate and scan your subscription." />
            </div>
            <div className="bg-slate-50/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-xl border border-slate-200 dark:border-slate-700 p-6 mt-4 shadow-xl shadow-indigo-500/10">
              <Form form={form} layout="vertical">
                <Form.Item name="subscription_id" label={<span className="text-lg font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">Subscription ID</span>} rules={[{ required: true, message: "Please enter your Subscription ID!" }]}>
                  <Input placeholder="e.g. a2b28c85-1948-4263-90ca-bade2bac4df4" className="h-12 rounded-xl w-full dark:text-white border-slate-500 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50" />
                </Form.Item>
                <Form.Item name="tenant_id" label={<span className="text-lg font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">Tenant ID</span>} rules={[{ required: true, message: "Please enter your Tenant ID!" }]}>
                  <Input placeholder="e.g. 4dbe5f90-7914-4e24-bc2f-2666eed5dd31" className="h-12 rounded-xl w-full dark:text-white border-slate-500 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50" />
                </Form.Item>
                <Form.Item name="client_id" label={<span className="text-lg font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">Client ID (App ID)</span>} rules={[{ required: true, message: "Please enter your Client ID!" }]}>
                  <Input placeholder="e.g. 9c7beabf-44e8-481c-adcd-a452c6877561" className="h-12 rounded-xl w-full dark:text-white border-slate-500 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50" />
                </Form.Item>
                <Form.Item name="client_secret" label={<span className="text-lg font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">Client Secret</span>} rules={[{ required: true, message: "Please enter your Client Secret!" }]}>
                  <Input.Password placeholder="Enter Client Secret" className="h-12 rounded-xl w-full dark:text-white border-slate-500 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50" />
                </Form.Item>
                <Form.Item name="subscription_name" label={<span className="text-lg font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">Subscription Name (Optional)</span>} rules={[{ required: false }]}>
                  <Input placeholder="e.g. Production, Dev, Staging" className="h-12 rounded-xl w-full dark:text-white border-slate-500 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50" />
                </Form.Item>
              </Form>
            </div>
            <div className="mt-6 flex justify-between">
              <Button
                icon={<ArrowLeft className="w-4 h-4" />}
                onClick={() => setStep(1)}
                className="font-semibold px-5 py-2 h-auto rounded-xl transition-all duration-200"
              >
                Back to Setup Guide
              </Button>
              <Button
                disabled={loading}
                className="!bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                onClick={handleSubmit}
              >
                {loading ? (
                  <span className="flex items-center gap-2">Saving Subscription<Spinner /></span>
                ) : (
                  <span>Save Subscription</span>
                )}
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
