import { useState } from "react";
import { Button, Input, Form } from "antd";
import { X } from "lucide-react";
import Cookies from "js-cookie";
import { useNavigate } from "react-router-dom";
import { notifyError, notifySuccess, notifyInfo } from "./Notification";
import Spinner from "./UI/Spinner";
import { GetNote } from "./Utils";

export default function AzureRoleCreation({ onClose }) {
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async () => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;
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
      const response = await fetch(`${backend_url}/api/saveroleinfo`, {
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
        <div className="mt-6 flex justify-end">
          <Button disabled={loading} className="!bg-gradient-to-r from-blue-600 to-indigo-700 hover:from-blue-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105" onClick={handleSubmit}>
            {loading ? (<span className="flex items-center gap-2">Saving Subscription<Spinner /></span>) : (<span>Save Subscription</span>)}
          </Button>
        </div>
      </div>
    </div>
  );
}
