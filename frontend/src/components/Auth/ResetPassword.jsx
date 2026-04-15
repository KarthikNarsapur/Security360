import { useState, useRef, useEffect } from "react";
import { Button, Form, Input } from "antd";
import { useLocation, useNavigate } from "react-router-dom";
import PasswordChecklist from "react-password-checklist";
import { notifyError, notifySuccess } from "../Notification";
import { PiKeyBold } from "react-icons/pi";
import { RefreshCw } from "lucide-react";
import Spinner from "../UI/Spinner";

const CustomOTPInput = ({
  value,
  onChange,
  OTPLength = 6,
  autoFocus = true,
  disabled = false,
}) => {
  const inputRefs = useRef([]);

  useEffect(() => {
    inputRefs.current = inputRefs.current.slice(0, OTPLength);
  }, [value, OTPLength]);

  const handleChange = (index, newValue) => {
    if (!/^[0-9]?$/.test(newValue)) return;
    const newOtp = (value || "").padEnd(OTPLength, "").split("");
    newOtp[index] = newValue;
    const updatedValue = newOtp.join("").slice(0, OTPLength);
    onChange(updatedValue);
    if (newValue && index < OTPLength - 1) {
      inputRefs.current[index + 1]?.focus();
    }
  };

  const handlePaste = (e, startIndex) => {
    e.preventDefault();
    const pastedData = e.clipboardData.getData("text").trim();
    if (!/^\d{6}$/.test(pastedData)) {
      notifyError("Please paste a valid 6-digit numeric OTP");
      return;
    }

    const pastedDigits = pastedData.slice(0, OTPLength);
    onChange(pastedDigits);

    const nextFocusIndex = OTPLength - 1;
    if (inputRefs.current[nextFocusIndex]) {
      inputRefs.current[nextFocusIndex].focus();
    }
  };

  const handleKeyDown = (e, index) => {
    if (e.key === "Backspace" && !value?.[index] && index > 0) {
      if (inputRefs.current[index - 1]) {
        inputRefs.current[index - 1].focus();
      }
    } else if (e.key === "ArrowLeft" && index > 0) {
      if (inputRefs.current[index - 1]) {
        inputRefs.current[index - 1].focus();
      }
    } else if (e.key === "ArrowRight" && index < OTPLength - 1) {
      if (inputRefs.current[index + 1]) {
        inputRefs.current[index + 1].focus();
      }
    }
  };

  return (
    <div className="otp-input-container flex justify-center gap-2">
      {Array(OTPLength)
        .fill(0)
        .map((_, index) => (
          <input
            key={index}
            type="text"
            maxLength={1}
            value={value?.[index] || ""}
            onChange={(e) => handleChange(index, e.target.value)}
            onPaste={(e) => handlePaste(e, index)}
            onKeyDown={(e) => handleKeyDown(e, index)}
            onFocus={() => {
              if (inputRefs.current[index]) {
                inputRefs.current[index].focus();
              }
            }}
            ref={(el) => (inputRefs.current[index] = el)}
            disabled={disabled}
            className="w-[45px] h-[45px] text-center text-[18px] border-2 border-[#e2e8f0] rounded-[12px] bg-[rgba(255,255,255,0.5)] backdrop-blur-[4px] transition-all duration-200 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
            autoFocus={autoFocus && index === 0}
          />
        ))}
    </div>
  );
};

function ResetPassword() {
  const navigate = useNavigate();
  const location = useLocation();
  const [form] = Form.useForm();
  const [password, setPassword] = useState("");
  const [passwordAgain, setPasswordAgain] = useState("");
  const [isPasswordFocused, setIsPasswordFocused] = useState(false);
  const [loading, setLoading] = useState(false);
  const [loadingResendCode, setLoadingResendCode] = useState(false);

  const userData = location.state?.username || "";

  const onFinish = async (values) => {
    if (loading) {
      return;
    }
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    try {
      setLoading(true);
      const payload = {
        username: userData || "",
        password: password,
        confirmation_code: values.code,
      };
      if (!payload.username || payload.username.trim() === "") {
        navigate("/login");
        return;
      }

      if (!payload.password || payload.password.trim() === "") {
        notifyError("Password cannot be empty.");
        return;
      }

      if (
        !payload.confirmation_code ||
        payload.confirmation_code.trim().length !== 6
      ) {
        notifyError("Confirmation code must be exactly 6 digits.");
        return;
      }
      const response = await fetch(`${backend_url}/api/resetpassword`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response?.json();
      if (result.status === "ok") {
        notifySuccess("Password reset successfully");
        navigate("/login");
      } else {
        notifyError(result.error_message);
      }
    } catch (err) {
      console.log("error: ", err);
    } finally {
      setLoading(false);
    }
  };

  const resendCode = async () => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    if (loadingResendCode) {
      return;
    }
    try {
      setLoadingResendCode(true);
      const payload = {
        username: userData,
      };
      const response = await fetch(`${backend_url}/api/resendcode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response?.json();

      if (result?.status === "ok") {
        notifySuccess(
          `Code sent successfully to ${result?.response?.CodeDeliveryDetails?.Destination}`
        );
      } else {
        notifyError(
          `Error occurred verifying code...${result?.error.response.Error.Message}`
        );
      }
    } catch (err) {
      console.log("error: ", err);
    } finally {
      setLoadingResendCode(false);
    }
  };

  const onFinishFailed = (errorInfo) => {
    console.log("Password Reset Failed", errorInfo);
  };

  return (
    <div className="min-h-[631px] bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-md">
        <Form
          form={form}
          name="resetPassword"
          layout="vertical"
          size="large"
          labelCol={{ span: 24 }}
          wrapperCol={{ span: 24 }}
          initialValues={{ remember: true, code: "" }}
          onFinish={onFinish}
          onFinishFailed={onFinishFailed}
          autoComplete="off"
          className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-8 border border-indigo-100 dark:border-slate-700 animate-fade-in-up"
        >
          {/* Header */}
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
              Reset Password
            </h2>
            <p className="text-slate-600 dark:text-slate-400 mt-2">
              Enter the code and create a new password
            </p>
          </div>

          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Verification Code
              </span>
            }
            name="code"
            rules={[
              { required: true, message: "Please enter confirmation code" },
            ]}
            style={{ marginBottom: "20px" }}
          >
            <CustomOTPInput
              value={form.getFieldValue("code") || ""}
              onChange={(value) => form.setFieldsValue({ code: value })}
              autoFocus
              OTPLength={6}
              disabled={false}
            />
          </Form.Item>

          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                New Password
              </span>
            }
            name="password"
            rules={[{ required: true, message: "Please enter new password!" }]}
            style={{ marginBottom: "16px" }}
          >
            <Input.Password
              placeholder="Enter your new password"
              prefix={
                <PiKeyBold className="text-slate-400 font-extrabold text-lg" />
              }
              onChange={(e) => setPassword(e.target.value)}
              onFocus={() => setIsPasswordFocused(true)}
              onBlur={() => setIsPasswordFocused(false)}
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Confirm Password
              </span>
            }
            name="passwordagain"
            rules={[
              { required: true, message: "Please confirm your new password!" },
            ]}
            style={{ marginBottom: isPasswordFocused ? "16px" : "24px" }}
          >
            <Input.Password
              placeholder="Confirm your new password"
              prefix={
                <PiKeyBold className="text-slate-400 font-extrabold text-lg" />
              }
              onChange={(e) => setPasswordAgain(e.target.value)}
              onFocus={() => setIsPasswordFocused(true)}
              onBlur={() => setIsPasswordFocused(false)}
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          {isPasswordFocused && (
            <div className="mb-6 p-4 dark:text-white bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-200 dark:border-slate-600 animate-slide-down">
              <PasswordChecklist
                rules={[
                  "minLength",
                  "specialChar",
                  "number",
                  "capital",
                  "match",
                ]}
                minLength={5}
                value={password}
                valueAgain={passwordAgain}
                onChange={(isValid) => {}}
                className="text-sm"
              />
            </div>
          )}

          <Form.Item style={{ marginBottom: "20px" }}>
            <Button
              type="primary"
              htmlType="submit"
              className={`btn-primary h-12 w-full text-base font-semibold !bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 px-6 py-2 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-10 ${
                loading && "cursor-not-allowed opacity-70"
              }`}
              disabled={loading}
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <Spinner />
                  Resetting Password...
                </span>
              ) : (
                <span>Reset Password</span>
              )}
            </Button>
          </Form.Item>

          <Form.Item className="text-center" style={{ marginBottom: "0" }}>
            <span className="text-slate-600 dark:text-slate-400">
              Didn't receive the code?{" "}
            </span>
            <button
              type="button"
              onClick={resendCode}
              disabled={loadingResendCode}
              className={`text-indigo-600 dark:text-indigo-400 hover:text-indigo-400 dark:hover:text-indigo-300 font-medium transition-colors duration-200 ${
                loadingResendCode && "cursor-not-allowed opacity-70"
              }`}
            >
              {loadingResendCode ? "Sending..." : "Resend Code"}
            </button>
          </Form.Item>
        </Form>
      </div>
    </div>
  );
}

export default ResetPassword;
