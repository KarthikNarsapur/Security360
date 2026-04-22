import { useState } from "react";
import { Button, Form, Input } from "antd";
import { useNavigate } from "react-router-dom";
import { notifyError, notifySuccess } from "../Notification";
import Cookies from "js-cookie";
import { LuCircleUserRound } from "react-icons/lu";
import { PiKeyBold } from "react-icons/pi";
import { Shield } from "lucide-react";
import Spinner from "../UI/Spinner";
import { useCheckLoggedIn } from "../Utils";

const Login = () => {
  useCheckLoggedIn();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const onFinish = async (values) => {
    if (loading) {
      return;
    }
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    try {
      setLoading(true);
      const response = await fetch(`${backend_url}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
      const result = await response?.json();
      if (result.status === "ok") {
        const { AccessToken, IdToken, RefreshToken, ExpiresIn } =
          result.response.AuthenticationResult;

        const expiresInDays = ExpiresIn / (60 * 60 * 24);
        Cookies.set("access_token", AccessToken, { expires: expiresInDays });
        Cookies.set("id_token", IdToken, { expires: expiresInDays });
        Cookies.set("refresh_token", RefreshToken, { expires: 7 });
        localStorage.removeItem("username");
        localStorage.removeItem("full_name");
        localStorage.removeItem("account_details");
        localStorage.removeItem("eks_account_details");

        // localStorage.setItem("username", values.username);

        notifySuccess("Logged in successfully");
        navigate("/dashboard");
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
    console.log("Login Failed:", errorInfo);
  };

  return (
    <div className="bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-md">
        <Form
          name="login"
          layout="vertical"
          size="large"
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
              Welcome Back
            </h2>
            <p className="text-slate-600 dark:text-slate-400 mt-2">
              Sign in to your account
            </p>
          </div>

          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Username / Email
              </span>
            }
            name="username"
            rules={[
              {
                required: true,
                message: "Please input your username / email!",
              },
            ]}
            style={{ marginBottom: "20px" }}
          >
            <Input
              placeholder="Enter your username / email"
              prefix={
                <LuCircleUserRound className="text-slate-400 font-bold text-xl" />
              }
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Password
              </span>
            }
            name="password"
            rules={[{ required: true, message: "Please input your password!" }]}
            style={{ marginBottom: "12px" }}
          >
            <Input.Password
              placeholder="Enter your password"
              prefix={
                <PiKeyBold className="text-slate-400 font-extrabold text-lg" />
              }
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          <Form.Item className="text-right" style={{ marginBottom: "24px" }}>
            <span
              className="text-sm text-indigo-600 dark:text-indigo-400 cursor-pointer hover:text-indigo-400 dark:hover:text-indigo-300 font-medium transition-colors duration-200"
              onClick={() => navigate("/forgot")}
            >
              Forgot Password?
            </span>
          </Form.Item>

          <Form.Item style={{ marginBottom: "20px" }}>
            <Button
              type="primary"
              htmlType="submit"
              className={`btn-primary ${loading ? "btn-primary-loading" : ""}`}
              disabled={loading}
              loading={loading}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  Signing in...
                </span>
              ) : (
                <span>Sign In</span>
              )}
            </Button>
          </Form.Item>

          <Form.Item className="text-center" style={{ marginBottom: "0" }}>
            <span className="text-slate-600 dark:text-slate-400">
              Don't have an account?{" "}
            </span>
            <span
              className="text-indigo-600 dark:text-indigo-400 cursor-pointer hover:text-indigo-400 dark:hover:text-indigo-300 font-semibold transition-colors duration-200"
              onClick={() => navigate("/signup")}
            >
              Sign Up
            </span>
          </Form.Item>
        </Form>
      </div>
    </div>
  );
};

export default Login;
