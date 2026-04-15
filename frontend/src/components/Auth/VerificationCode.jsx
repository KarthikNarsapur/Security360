import { useState, useRef, useEffect } from "react";
import { Button, Form, Input } from "antd";
import { useLocation, useNavigate } from "react-router-dom";
import { notifyError, notifySuccess } from "../Notification";
import { ArrowLeft } from "lucide-react";
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

const VerificationCode = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [form] = Form.useForm();
  const [loading, setLoading] = useState(false);
  const [resendCodeLoading, setResendCodeLoading] = useState(false);

  const userData = location.state?.userData || {};

  const onFinish = async (values) => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    if (!backend_url) {
      console.log("Error: REACT_APP_BACKEND_URL is not defined");
      return;
    }
    try {
      setLoading(true);
      const payload = {
        confirm_user: {
          username: userData.username,
          confirmation_code: values.code,
        },
        user: {
          username: userData.username,
          full_name: userData.full_name,
          email: userData.email,
          company: userData.company,
          mobile_number: userData.mobile,
          role: userData.role,
        },
      };

      if (!payload.confirm_user.username) {
        notifyError("Username is missing. Please try again.");
        return;
      }
      if (!payload.confirm_user.confirmation_code) {
        notifyError("OTP is missing. Please enter the 6-digit code.");
        return;
      }
      if (payload.confirm_user.confirmation_code.length !== 6) {
        notifyError("Invalid OTP. It must be a 6-digit code.");
        return;
      }
      const response = await fetch(`${backend_url}/api/confirmsignup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const result = await response.json();
      console.log("result: ", result);

      if (result?.status === "ok") {
        notifySuccess("Code verified successfully");
        navigate("/login");
      } else {
        console.log("in else");
        console.log("first: ", result?.error_message);
        notifyError(result?.error_message || "Verification failed");
      }
    } catch (err) {
      console.log("Error in onFinish:", err);
      notifyError("An error occurred while verifying the code");
    } finally {
      setLoading(false);
    }
  };

  const onFinishFailed = (errorInfo) => {
    console.log("Verification Failed:", errorInfo);
  };

  const resendCode = async () => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    if (!backend_url) {
      console.log("Error: REACT_APP_BACKEND_URL is not defined");
      notifyError("Backend URL is not configured");
      return;
    }
    try {
      setResendCodeLoading(true);
      const payload = {
        username: userData.username,
      };
      const response = await fetch(`${backend_url}/api/resendcode`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const result = await response.json();

      if (result?.status === "ok") {
        notifySuccess(
          `Code sent successfully to ${result?.response?.CodeDeliveryDetails?.Destination}`
        );
      } else {
        notifyError(
          `Error occurred resending code: ${
            result?.error?.response?.Error?.Message || "Unknown error"
          }`
        );
      }
    } catch (err) {
      notifyError("An error occurred while resending the code");
    } finally {
      setResendCodeLoading(false);
    }
  };

  return (
    <div className="bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-md">
        <Form
          form={form}
          name="verification"
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
              Verify Your Account
            </h2>
            <p className="text-slate-600 dark:text-slate-400 mt-2">
              Enter the 6-digit code sent to your email
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
            style={{ marginBottom: "32px" }}
          >
            <CustomOTPInput
              value={form.getFieldValue("code") || ""}
              onChange={(value) => form.setFieldsValue({ code: value })}
              autoFocus
              OTPLength={6}
              disabled={false}
            />
          </Form.Item>

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
                  Verifying...
                </span>
              ) : (
                <span>Verify Account</span>
              )}
            </Button>
          </Form.Item>

          <Form.Item className="text-center" style={{ marginBottom: "16px" }}>
            <span className="text-slate-600 dark:text-slate-400">
              Didn't receive the code?{" "}
            </span>
            <button
              type="button"
              onClick={resendCode}
              disabled={resendCodeLoading}
              className={`text-indigo-600 dark:text-indigo-400 hover:text-indigo-400 dark:hover:text-indigo-300 font-medium transition-colors duration-200 ${
                resendCodeLoading && "cursor-not-allowed opacity-70"
              }`}
            >
              {resendCodeLoading ? "Sending..." : "Resend Code"}
            </button>
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
};

export default VerificationCode;
