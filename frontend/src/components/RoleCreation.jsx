import React, { useState } from "react";
import { Button, message, Steps, theme, Input, Form } from "antd";
import { ImCross } from "react-icons/im";
import { FiDownload } from "react-icons/fi";
import { generateCloudFormationTemplate } from "./CloudFormationTemplate";
import Cookies from "js-cookie";
import { useNavigate } from "react-router-dom";
import { X, Download, Play } from "lucide-react";
import { FaStarOfLife } from "react-icons/fa";
import { notifyError, notifySuccess } from "./Notification";
import Spinner from "./UI/Spinner";
import { LuNotebookPen } from "react-icons/lu";
import { GetNote } from "./Utils";

const downloadInfraCFTYAML = async () => {
  const CFT_S3_URL = process.env.REACT_APP_INFRA_CF_TEMPLATE_URL;

  try {
    const response = await fetch(CFT_S3_URL);
    if (response.ok) {
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "infra-cloudformation.yaml";
      link.click();
      notifySuccess("YAML downloaded");
    } else {
      throw new Error("Failed to fetch the YAML file.");
    }
  } catch (error) {
    console.error("Download failed:", error);
    notifyError("Download failed");
  }
};

export default function RoleCreation({ onClose }) {
  const { token } = theme.useToken();
  const [current, setCurrent] = useState(0);
  const [form1] = Form.useForm();
  const [form3] = Form.useForm();
  const [isDoneDisabled, setIsDoneDisabled] = useState(true);
  const [accountId, setAccountId] = useState("");
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const steps = [
    // {
    //   title: "Get Account ID",
    //   content: (
    //     <Form form={form1} name="account-form" layout="horizontal">
    //       <h2 className="text-lg font-bold mb-6 bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
    //         Step 1: Enter your Account ID{" "}
    //         <sup>
    //           <FaStarOfLife className="text-red-700 inline-block" size={8} />
    //         </sup>
    //       </h2>
    //       <Form.Item
    //         name="account_id"
    //         rules={[
    //           {
    //             required: true,
    //             message: "Please enter your Account ID!",
    //           },
    //           {
    //             pattern: /^\d{12}$/,
    //             message: "Account ID must be exactly 12 digits!",
    //           },
    //         ]}
    //       >
    //         <Input
    //           placeholder="Enter your Account ID"
    //           className="h-12 rounded-xl w-96 dark:text-white border-slate-200 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200 placeholder:text-slate-400!important dark:placeholder:text-slate-300!important"
    //         />
    //       </Form.Item>
    //     </Form>
    //   ),
    // },
    {
      title: "Create Role",
      content: (
        <div>
          <h2 className="text-lg font-bold mb-6 bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
            Step 1: Choose Role Creation Method
          </h2>
          <div className="flex gap-6 mt-4 h-full">
            {/* Left Half - Options 1 & 2 */}
            <div className="flex-1 flex flex-col items-center space-y-6">
              {/* Option 1: Create Stack */}
              <div className="flex flex-col items-center space-y-2">
                <h3 className="text-md font-semibold text-slate-700 dark:text-slate-300">
                  Option 1: Create via CloudFormation Stack
                </h3>
                <Button
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                  onClick={() => {
                    const url = process.env.REACT_APP_CF_URL;
                    if (url) {
                      window.open(url, "_blank", "noopener,noreferrer");
                    } else {
                      notifyError("URL not defined in environment");
                    }
                  }}
                >
                  Create Stack
                </Button>
              </div>

              <div className="w-full border-t border-slate-200 dark:border-slate-600"></div>

              {/* Option 2: Download Template */}
              <div className="flex flex-col items-center space-y-2">
                <h3 className="text-md font-semibold text-slate-700 dark:text-slate-300">
                  Option 2: Download CloudFormation Template
                </h3>
                <Button
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                  icon={<Download className="w-4 h-4" />}
                  onClick={downloadInfraCFTYAML}
                >
                  Download YAML
                </Button>
              </div>
            </div>

            {/* Vertical Divider */}
            <div className="w-px bg-slate-200 dark:bg-slate-600"></div>

            {/* Right Half - Option 3 */}
            <div className="flex-1 flex flex-col items-center justify-center space-y-2">
              <h3 className="text-md font-semibold text-slate-700 dark:text-slate-300">
                Option 3: Manual Role Creation
              </h3>
              <p className="text-sm text-slate-600 dark:text-slate-400 text-center mb-4">
                Download detailed step-by-step instructions
              </p>
              <Button
                className="!bg-gradient-to-r from-green-600 to-green-700 hover:from-green-700 hover:to-green-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                icon={<FiDownload className="w-4 h-4" />}
                onClick={async () => {
                  const sopPdfS3Url =
                    process.env.REACT_APP_INFRA_SCAN_SOP_PDF_S3_URL || "";
                  if (sopPdfS3Url) {
                    const response = await fetch(sopPdfS3Url, { mode: "cors" });
                    if (!response.ok) {
                      notifyError("Failed to fetch PDF");
                      return;
                    }

                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const link = document.createElement("a");
                    link.href = url;
                    link.download = "infra-manual-role-creation-steps.pdf";
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    window.URL.revokeObjectURL(url);
                    notifySuccess("SOP PDF downloaded");
                  } else {
                    notifyError("PDF URL not configured");
                  }
                }}
              >
                Download SOP PDF
              </Button>
            </div>
          </div>
        </div>
      ),
    },
    {
      title: "Provide Role details",
      content: (
        <Form
          form={form3}
          name="account-form"
          layout="horizontal"
          className="flex flex-col items-center"
          onFieldsChange={() => {
            const hasErrors = form3
              .getFieldsError()
              .some(({ errors }) => errors.length > 0);
            const roleArnTouched = form3.isFieldTouched("role_arn");
            const roleArnValue = form3.getFieldValue("role_arn");
            setIsDoneDisabled(!roleArnTouched || !roleArnValue || hasErrors);
          }}
        >
          <h2 className="text-lg font-bold mb-6 bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
            Step 2: Provide Role Details{" "}
            <sup>
              <FaStarOfLife className="text-red-700 inline-block" size={8} />
            </sup>
          </h2>
          <Form.Item
            name="role_arn"
            rules={[
              {
                required: true,
                message: "Please enter Role ARN!",
              },

              // {
              //   pattern: /^arn:aws:iam::\d{12}:role\/Sec360-InfraScan-Role$/,
              //   message:
              //     "Role ARN must be in the format arn:aws:iam::[12-digit-account-id]:role/Sec360-InfraScan-Role",
              // },

              // {
              //   validator: (_, value) => {
              //     if (!value) return Promise.resolve();
              //     const match = value.match(
              //       /^arn:aws:iam::(\d{12}):role\/[a-zA-Z_0-9+=,.@-]{1,64}$/
              //     );
              //     if (match) {
              //       const extractedId = match[1];
              //       if (extractedId !== accountId) {
              //         return Promise.reject(
              //           new Error(
              //             `Account ID in Role ARN (${extractedId}) does not match the entered Account ID (${accountId})!`
              //           )
              //         );
              //       }
              //     }
              //     return Promise.resolve();
              //   },
              // },
            ]}
          >
            <Input
              placeholder="Enter Role ARN"
              className="h-12 rounded-xl w-96 dark:text-white border-slate-500 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200 placeholder:text-slate-400!important dark:placeholder:text-slate-300!important"
            />
          </Form.Item>
          {/* <h2 className="text-lg font-bold mb-6 bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
            Enter Account Name{" "}
          </h2> */}
          <Form.Item
            name="account_name"
            rules={[
              {
                required: false,
                message: "Account name is optional",
              },
            ]}
          >
            <Input
              placeholder="Enter Account Name (Optional)"
              className="h-12 rounded-xl w-96 dark:text-white border-slate-500 dark:border-slate-600 bg-white/50 dark:bg-slate-800/50 backdrop-blur-sm hover:border-indigo-300 focus:border-indigo-500 transition-all duration-200 placeholder:text-slate-800!important dark:placeholder:text-slate-300!important"
            />
          </Form.Item>
        </Form>
      ),
    },
  ];

  const handleSubmit = async () => {
    const backend_url = process.env.REACT_APP_BACKEND_URL;
    const values3 = await form3.validateFields();
    const access_token = Cookies.get("access_token");
    const account_id_from_role_arn =
      values3.role_arn.match(
        /^arn:aws:iam::(\d{12}):role\/Sec360-InfraScan-Role$/
      )[1] || "";

    const payload = {
      roles: [
        {
          account_id: account_id_from_role_arn,
          role_arn: values3.role_arn,
          account_name: values3.account_name || "",
        },
      ],
      access_token: access_token,
      role_type: "infra",
    };
    if (!payload.roles[0].account_id || !payload.roles[0].role_arn) {
      notifyError("Missing required fields!");
      return;
    }
    if (!payload.access_token) {
      notifyError("Session expired. Please login again.");
      navigate("/login");
      return;
    }
    // console.log("payload: ", payload);

    try {
      setLoading(true);
      const response = await fetch(`${backend_url}/api/saveroleinfo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      if (result.status === "ok") {
        notifySuccess("Account Saved Successfully");
        const existingAccountDetails =
          JSON.parse(localStorage.getItem("account_details") || "[]") || [];

        // Add the new role details to the account details
        const updatedAccountDetails = [
          ...existingAccountDetails,
          payload.roles[0],
        ];

        // Save the updated account details back to cookies
        localStorage.setItem(
          "account_details",
          JSON.stringify(updatedAccountDetails)
        );
        onClose();
      } else {
        notifyError(result.error_message);
      }
    } catch (err) {
      console.log("error: ", err);
      notifyError("Something went wrong");
    } finally {
      setLoading(false);
    }
  };

  const next = () => setCurrent(current + 1);
  const prev = () => setCurrent(current - 1);

  const items = steps.map((item) => ({
    key: item.title,
    title: item.title,
  }));

  return (
    <div className="fixed top-0 left-0 w-full h-full bg-black bg-opacity-40 z-50 flex items-center justify-center">
      <div className="bg-white w-2/3 max-h-[90vh] overflow-y-auto p-6 relative bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg rounded-2xl shadow-2xl shadow-slate-900/20 border border-slate-200 dark:border-slate-700">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-lg p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
        >
          <X className="w-5 h-5 text-slate-600 dark:text-slate-400" />
        </button>

        <h3 className="text-2xl font-bold mb-4 bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
          Create Role
        </h3>
        <div>
          <GetNote note="Please read the instructions carefully on the Home page before getting started." />
        </div>
        <Steps
          current={current}
          items={items}
          className="[&_.ant-steps-item-finish_.ant-steps-item-icon]:!bg-gradient-to-r 
    [&_.ant-steps-item-finish_.ant-steps-item-icon]:!from-indigo-600 
    [&_.ant-steps-item-finish_.ant-steps-item-icon]:!to-purple-600
    [&_.ant-steps-item-process_.ant-steps-item-icon]:!bg-gradient-to-r 
    [&_.ant-steps-item-process_.ant-steps-item-icon]:!from-indigo-600 
    [&_.ant-steps-item-process_.ant-steps-item-icon]:!to-purple-600
    [&_.ant-steps-item-finish_.ant-steps-item-title]:!text-slate-900
    [&_.ant-steps-item-process_.ant-steps-item-title]:!text-slate-900
    [&_.ant-steps-item-wait_.ant-steps-item-title]:!text-slate-500
    dark:[&_.ant-steps-item-finish_.ant-steps-item-title]:!text-slate-100
    dark:[&_.ant-steps-item-process_.ant-steps-item-title]:!text-slate-100
    dark:[&_.ant-steps-item-wait_.ant-steps-item-title]:!text-slate-400
    [&_.ant-steps-item-finish_.ant-steps-item-tail]:after:!bg-gradient-to-r
    [&_.ant-steps-item-finish_.ant-steps-item-tail]:after:!from-indigo-600
    [&_.ant-steps-item-finish_.ant-steps-item-tail]:after:!to-purple-600
    [&_.ant-steps-item-wait_.ant-steps-item-icon]:!bg-slate-200
    [&_.ant-steps-item-wait_.ant-steps-item-icon]:!border-slate-300
    dark:[&_.ant-steps-item-wait_.ant-steps-item-icon]:!bg-slate-700
    dark:[&_.ant-steps-item-wait_.ant-steps-item-icon]:!border-slate-600
  "
        />

        <div className="bg-slate-50/80 dark:bg-slate-800/80 backdrop-blur-sm rounded-xl border border-slate-200 dark:border-slate-700 p-6 text-center min-h-[300px] max-h-[300px] overflow-hidden flex flex-col justify-center mt-4 shadow-xl shadow-indigo-500/10">
          {steps[current].content}
        </div>

        <div className="mt-6 flex justify-between">
          {current > 0 ? (
            <Button
              className="!bg-white/80 dark:!bg-slate-800/80 backdrop-blur-sm !border-2 !border-indigo-600 dark:!border-indigo-400 !text-indigo-600 dark:!text-indigo-400 hover:!bg-indigo-50 dark:hover:!bg-indigo-900/20 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              onClick={prev}
            >
              Previous
            </Button>
          ) : (
            <div />
          )}

          {current < steps.length - 1 ? (
            <Button
              className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
              onClick={next}
            >
              Next
            </Button>
          ) : (
            <Button
              disabled={isDoneDisabled || loading}
              className={`!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 !text-white hover:!text-white !border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 ${
                isDoneDisabled ? "opacity-70" : ""
              }`}
              onClick={handleSubmit}
            >
              {loading ? (
                <span className="flex items-center gap-2">
                  Saving Account
                  <Spinner />
                </span>
              ) : (
                <span>Done</span>
              )}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}
