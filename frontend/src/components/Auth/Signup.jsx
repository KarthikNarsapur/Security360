import { useState } from "react";
import { Button, Form, Input, Select } from "antd";
import { useNavigate } from "react-router-dom";
import { notifySuccess, notifyError, notifyInfo } from "../Notification";
import PasswordChecklist from "react-password-checklist";
import { LuCircleUserRound } from "react-icons/lu";
import { PiKeyBold } from "react-icons/pi";
import { FaRegUser } from "react-icons/fa";
import { HiOutlineMail } from "react-icons/hi";
import { MdBusiness } from "react-icons/md";
import { FiPhone } from "react-icons/fi";
import { MdWorkOutline } from "react-icons/md";
import { LiaAddressCardSolid } from "react-icons/lia";
import { UserPlus } from "lucide-react";
import Spinner from "../UI/Spinner";
import Cookies from "js-cookie";
import { useCheckLoggedIn } from "../Utils";

const Signup = () => {
  useCheckLoggedIn();
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [passwordAgain, setPasswordAgain] = useState("");
  const [isPasswordFocused, setIsPasswordFocused] = useState(false);
  const [loading, setLoading] = useState(false);
  const [role, setRole] = useState("");

  const maskEmail = (email) => {
    const [localPart, domain] = email.split("@");
    if (localPart.length <= 3) {
      return `${localPart[0]}***@${domain}`;
    }
    return `${localPart.slice(0, 3)}***@${domain}`;
  };

  const handleSubmit = async (values) => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;

    try {
      setLoading(true);
      const response = await fetch(`${backend_url}/api/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });
      const result = await response.json();
      if (result.status === "ok" || result.status === "unconfirmed") {
        // Success or unconfirmed (code resent)
        if (result.status === "ok") {
          notifySuccess(
            `Code Sent Successfully to Mail ${maskEmail(values.email)}`
          );
        } else {
          notifyInfo(
            `User already exists but unconfirmed. Code resent to Mail ${maskEmail(
              values.email
            )}`
          );
        }

        navigate("/verification", {
          state: {
            userData: {
              username: values.username || "",
              full_name: values.full_name || "",
              email: values.email || "",
              company: values.organization || "",
              mobile: values.mobile || "",
              role: values.role || "",
            },
          },
        });
      } else {
        notifyError(result.error_message);
      }
    } catch (err) {
      console.log("error: ", err);
      notifyError(err);
    } finally {
      setLoading(false);
    }
  };

  const onFinishFailed = (errorInfo) => {
    console.log("Signup Failed:", errorInfo);
  };

  return (
    <div className="bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-md">
        <Form
          name="signup"
          layout="vertical"
          size="large"
          onFinish={handleSubmit}
          onFinishFailed={onFinishFailed}
          labelCol={{ span: 24 }}
          wrapperCol={{ span: 24 }}
          autoComplete="off"
          className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-8 border border-indigo-100 dark:border-slate-700 animate-fade-in-up"
        >
          {/* Header */}
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
              Create Account
            </h2>
            <p className="text-slate-600 dark:text-slate-400 mt-2">
              Join us today and get started
            </p>
          </div>

          {/* Full Name */}
          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Full Name
              </span>
            }
            name="full_name"
            rules={[
              { required: true, message: "Please input your full name!" },
            ]}
            style={{ marginBottom: "16px" }}
          >
            <Input
              placeholder="Enter your full name"
              prefix={
                <FaRegUser className="text-slate-400 font-bold text-lg" />
              }
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          {/* Username */}
          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Username
              </span>
            }
            name="username"
            rules={[{ required: true, message: "Please input a username!" }]}
            style={{ marginBottom: "16px" }}
          >
            <Input
              placeholder="Choose a username"
              prefix={
                <LuCircleUserRound className="text-slate-400 font-bold text-xl" />
              }
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          {/* Email */}
          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Email
              </span>
            }
            name="email"
            rules={[
              { required: true, message: "Please input your email!" },
              {
                pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
                message: "Please enter a valid email address",
              },
            ]}
            style={{ marginBottom: "16px" }}
          >
            <Input
              placeholder="Enter your email"
              prefix={
                <HiOutlineMail className="text-slate-400 font-bold text-xl" />
              }
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          {/* Mobile Number */}
          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Mobile Number
              </span>
            }
            name="mobile"
            rules={[
              { required: true, message: "Please input your mobile number!" },
              {
                pattern: /^[0-9]{10}$/,
                message: "Please enter a valid 10-digit mobile number",
              },
            ]}
            style={{ marginBottom: "16px" }}
          >
            <Input
              placeholder="Enter your mobile number"
              prefix={<FiPhone className="text-slate-400 font-bold text-lg" />}
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item>

          {/* Role */}
          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Role
              </span>
            }
            name="role"
            rules={[{ required: true, message: "Please select your role!" }]}
            style={{ marginBottom: "16px" }}
          >
            <Select
              placeholder="Select role"
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
              popupClassName="dark:bg-slate-800 dark:text-white"
              prefix={
                <MdWorkOutline className="text-slate-400 font-bold text-lg" />
              }
              onChange={(value) => setRole(value)}
            >
              <Option value="student">Student</Option>
              {/* <Option value="individual">Individual</Option> */}
              <Option value="organization">Organization</Option>
            </Select>
          </Form.Item>

          {/* Organization */}
          {role === "organization" && (
            <Form.Item
              label={
                <span className="text-slate-700 dark:text-slate-300 font-semibold">
                  Organization
                </span>
              }
              name="organization"
              rules={[
                { required: true, message: "Please input your organization!" },
              ]}
              style={{ marginBottom: "16px" }}
            >
              <Input
                placeholder="Enter your organization"
                prefix={
                  <MdBusiness className="text-slate-400 font-bold text-xl" />
                }
                className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
              />
            </Form.Item>
          )}

          {/* <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Address
              </span>
            }
            name="address"
            rules={[{ required: true, message: "Please input your address!" }]}
            style={{ marginBottom: "16px" }}
          >
            <Input
              placeholder="Enter your address"
              prefix={
                <LiaAddressCardSolid className="text-slate-400 font-bold text-xl" />
              }
              className="h-12 rounded-xl dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200"
            />
          </Form.Item> */}

          <Form.Item
            label={
              <span className="text-slate-700 dark:text-slate-300 font-semibold">
                Password
              </span>
            }
            name="password"
            rules={[{ required: true, message: "Please input your password!" }]}
            style={{ marginBottom: "16px" }}
          >
            <Input.Password
              placeholder="Create a password"
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
              { required: true, message: "Please confirm your password!" },
            ]}
            style={{ marginBottom: isPasswordFocused ? "16px" : "24px" }}
          >
            <Input.Password
              placeholder="Confirm your password"
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
                  "lowercase",
                  "match",
                ]}
                minLength={8}
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
                  Creating Account...
                </span>
              ) : (
                <span>Create Account</span>
              )}
            </Button>
          </Form.Item>

          <Form.Item className="text-center" style={{ marginBottom: "0" }}>
            <span className="text-slate-600 dark:text-slate-400">
              Already have an account?{" "}
            </span>
            <span
              className="text-indigo-600 dark:text-indigo-400 cursor-pointer hover:text-indigo-400 dark:hover:text-indigo-300 font-semibold transition-colors duration-200"
              onClick={() => navigate("/login")}
            >
              Sign In
            </span>
          </Form.Item>
        </Form>
      </div>
    </div>
  );
};

export default Signup;
