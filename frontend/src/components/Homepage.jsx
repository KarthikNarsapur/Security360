import React, { useEffect, useState } from "react";
import { Button } from "antd";
import RoleCreation from "./RoleCreation";
import Cookies from "js-cookie";
import { Circle } from "lucide-react";
import { notifySuccess } from "./Notification";
import { fetchUserDetails, GetNote } from "./Utils";
import { useNavigate } from "react-router-dom";

function HomePage({
  userName,
  fullName,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) {
  const [showRoleCreation, setShowRoleCreation] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const getUserData = async () => {
      const result = await fetchUserDetails({ navigate });
      if (result.status == "ok") {
        setUserName(result.userName);
        setFullName(result.fullName);
        setAccountDetails(result.accountDetails);
        setEksAccountDetails(result.eksAccountDetails);
      }
    };
    getUserData();
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="pl-12 p-6">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <div className="flex items-center justify-between bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 p-4 border border-indigo-100 dark:border-slate-700">
              <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
                Hi, {fullName}
              </h1>
              <Button
                className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:!from-indigo-700 hover:!to-indigo-800 hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 text-white"
                onClick={() => setShowRoleCreation(true)}
              >
                Get Started
              </Button>
            </div>
          </div>

          {/* <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 mb-6">
            <div>
              <h2 className="text-2xl font-bold text-indigo-900 dark:text-gray-200 mb-3">
                Step 1: Enter AWS Account ID
              </h2>
              <p className="text-slate-700 dark:text-white">
                Enter the 12-digit AWS Account ID of the account you want to
                scan for security and compliance checks. Ensure the ID is
                correct to avoid errors during the scan.
              </p>
            </div>
          </div> */}

          <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700 mb-6">
            <div>
              <h2 className="text-2xl font-bold text-indigo-900 dark:text-gray-200 mb-3">
                Step 1: Create the IAM Role
              </h2>
              <p className="text-slate-700 dark:text-white mb-4">
                Select one of the methods below to create the required IAM Role in your AWS account:
              </p>
              <ul className="space-y-3 text-slate-700 dark:text-white">
                <li className="flex items-start gap-2">
                  <Circle className="w-3 h-3 text-indigo-500 flex-shrink-0 fill-current relative top-[6px]" />
                  <div>
                    <strong className="font-semibold">
                      Create Role via CloudFormation Template:
                    </strong>{" "}
                    Redirects you to the AWS Console where you can deploy the CloudFormation stack to automatically create the required IAM Role.
                  </div>
                </li>
                <li className="flex items-start gap-2">
                  <Circle className="w-3 h-3 text-indigo-500 flex-shrink-0 fill-current relative top-[6px]" />
                  <div>
                    <strong className="font-semibold">
                      Download Template:
                    </strong>{" "}
                    <span
                      onClick={async () => {
                        const infra_cft_template_url =
                          process.env.REACT_APP_INFRA_CF_TEMPLATE_URL || "";

                        if (infra_cft_template_url) {
                          try {
                            const response = await fetch(
                              infra_cft_template_url,
                              {
                                mode: "cors",
                              }
                            );

                            if (!response.ok) {
                              notifyError("Failed to fetch CFT Template");
                              return;
                            }

                            const blob = await response.blob();
                            const url = window.URL.createObjectURL(blob);

                            const link = document.createElement("a");
                            link.href = url;
                            link.download = "infra-cft-template.yaml";
                            document.body.appendChild(link);
                            link.click();
                            document.body.removeChild(link);

                            window.URL.revokeObjectURL(url);
                            notifySuccess("CFT Template downloaded");
                          } catch (err) {
                            notifyError("Error downloading CFT Template");
                          }
                        } else {
                          notifyError("CFT Template URL not configured");
                        }
                      }}
                      className="text-indigo-600 underline cursor-pointer"
                    >
                      Download
                    </span>{" "}
                    the CloudFormation template in{" "}
                    <code className="bg-slate-100 dark:bg-slate-800 px-1.5 py-0.5 rounded text-sm font-mono">
                      .yaml
                    </code>{" "}
                    format. After downloading, visit the{" "}
                    <strong>Infrastructure as Code Composer</strong> in the AWS
                    Console, paste the contents of the YAML file, validate the
                    template for errors, and then proceed to create the stack
                    manually.
                  </div>
                </li>
                <li className="flex items-start gap-2">
                  <Circle className="w-3 h-3 text-indigo-500 flex-shrink-0 fill-current relative top-[6px]" />
                  <div>
                    <strong className="font-semibold">
                      Manual Role Creation:
                    </strong>{" "}
                    <span
                      onClick={async () => {
                        const sopPdfS3Url =
                          process.env.REACT_APP_INFRA_SCAN_SOP_PDF_S3_URL || "";
                        if (sopPdfS3Url) {
                          const response = await fetch(sopPdfS3Url, {
                            mode: "cors",
                          });
                          if (!response.ok) {
                            notifyError("Failed to fetch PDF");
                            return;
                          }

                          const blob = await response.blob();
                          const url = window.URL.createObjectURL(blob);
                          const link = document.createElement("a");
                          link.href = url;
                          link.download =
                            "infra-manual-role-creation-steps.pdf";
                          document.body.appendChild(link);
                          link.click();
                          document.body.removeChild(link);
                          window.URL.revokeObjectURL(url);
                          notifySuccess("SOP PDF downloaded");
                        } else {
                          notifyError("PDF URL not configured");
                        }
                      }}
                      className="text-indigo-600 underline cursor-pointer"
                    >
                      Download
                    </span>{" "}
                    the detailed SOP (Standard Operating Procedure) PDF that
                    contains step-by-step instructions for manually creating the
                    required IAM role. Follow the steps mentioned inside the PDF
                    document to create the role manually through the AWS
                    Console.
                  </div>
                </li>
              </ul>
            </div>
          </div>

          <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700">
            <div>
              <h2 className="text-2xl font-bold text-indigo-900 dark:text-gray-200 mb-3">
                Step 2: Provide IAM Role ARN
              </h2>
              <p className="text-slate-700 dark:text-white mb-4">
                Enter the ARN (Amazon Resource Name) of the IAM Role you created in Step 1.
                This role enables secure cross-account access so that Security360 can perform infrastructure security scans.
              </p>
              <div>
                <GetNote note="This Role is only for Infra Security scan." />
              </div>
            </div>
          </div>

          {showRoleCreation && (
            <RoleCreation onClose={() => setShowRoleCreation(false)} />
          )}
        </div>
      </div>
    </div>
  );
}

export default HomePage;
