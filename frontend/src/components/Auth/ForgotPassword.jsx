import { useState } from "react";
import { Button, Form, Input } from "antd";
import { notifySuccess, notifyError } from "../Notification";
import { useNavigate } from "react-router-dom";
import { LuCircleUserRound } from "react-icons/lu";
import { KeyRound, ArrowLeft } from "lucide-react";
import Spinner from "../UI/Spinner";

function ForgotPassword() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const onFinish = async (values) => {
    if (loading) {
      return;
    }
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    try {
      setLoading(true);
      const response = await fetch(`${backend_url}/api/forgotpassword`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
      const result = await response?.json();
      if (result.status === "ok") {
        notifySuccess(
          `Code sent successfully to ${result.response["CodeDeliveryDetails"]["Destination"]}`
        );
        navigate("/reset", { state: { username: values.username } });
      } else {
        notifyError(result.error_message);
      }
    } catch (err) {
      console.log("error: ", err);
    } finally {
      setLoading(false);
    }
  };

  const onFinishFailed = (errorInfo) => {
    console.log("Forgot Password Failed", errorInfo);
  };

  return (
    <div className="bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-md">
        <Form
          name="forgotPassword"
          size="large"
          layout="vertical"
          labelCol={{ span: 24 }}
          wrapperCol={{ span: 24 }}
          initialValues={{ remember: true }}
          onFinish={onFinish}
          onFinishFailed={onFinishFailed}
          autoComplete="off"
          className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-8 border border-indigo-100 dark:border-slate-700 animate-fade-in-up"
        >
          {/* Header */}
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
              Forgot Password
            </h2>
            <p className="text-slate-600 dark:text-slate-400 mt-2">
              Enter your username to receive a reset code
            </p>
          </div>

          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Username / Email
              </span>
            }
            name="username"
            rules={[{ required: true, message: "Please input your username / email!" }]}
            style={{ marginBottom: "24px" }}
          >
            <Input
              placeholder="Enter your username / email"
              prefix={
                <LuCircleUserRound className="text-slate-400 font-bold text-xl" />
              }
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          <Form.Item style={{ marginBottom: "20px" }}>
            <Button
              type="primary"
              htmlType="submit"
              className={`btn-primary h-12 w-full text-base font-semibold !bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 px-6 py-2 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-10${
                loading && "cursor-not-allowed opacity-70"
              }`}
              disabled={loading}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Spinner />
                  Sending Code...
                </span>
              ) : (
                <span>Send Reset Code</span>
              )}
            </Button>
          </Form.Item>

          <Form.Item className="text-center" style={{ marginBottom: "0" }}>
            <button
              type="button"
              onClick={() => navigate("/login")}
              className="flex items-center justify-center gap-2 text-indigo-600 dark:text-indigo-400 hover:text-indigo-400 dark:hover:text-indigo-300 font-medium transition-colors duration-200 mx-auto"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Sign In
            </button>
          </Form.Item>
        </Form>
      </div>
    </div>
  );
}

export default ForgotPassword;
