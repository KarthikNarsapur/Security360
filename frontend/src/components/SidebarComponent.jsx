import {
  FileSearchOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  HomeOutlined,
  SecurityScanOutlined,
  BarsOutlined,
} from "@ant-design/icons";
import { Layout, Menu, Button } from "antd";
import { useNavigate } from "react-router-dom";
import { AiOutlineKubernetes } from "react-icons/ai";
import { SiKubernetes } from "react-icons/si";
import { FaChartBar, FaShieldAlt, FaSearch, FaServer, FaAws } from "react-icons/fa";
import { VscAzure } from "react-icons/vsc";
import { BiLogoGoogleCloud } from "react-icons/bi";
import "./Scrollbar.css";
import { TbReportAnalytics } from "react-icons/tb";
import { RiDashboard3Line, RiShieldCheckLine } from "react-icons/ri";
import { useEffect, useState } from "react";
import { BiPulse } from "react-icons/bi";
import { MenuIcon } from "./Utils";

const { Sider } = Layout;

export default function SidebarComponent({
  collapsed,
  setCollapsed,
  selectedMenu,
  setSelectedMenu,
}) {
  const navigate = useNavigate();
  const [ipAllowed, setIpAllowed] = useState(false);
  const backend_url = process.env.REACT_APP_BACKEND_URL;

  useEffect(() => {
    const validateIp = async () => {
      try {
        const res = await fetch(`${backend_url}/api/validate-ip`);
        const data = await res.json();
        setIpAllowed(data.isAllowed);
        if (!data.allowed) {
          setSelectedMenu("home");
        }
      } catch (err) {
        console.error("IP validation failed", err);
      }
    };

    validateIp();
  }, []);

  const handleMenuClick = (e) => {
    setSelectedMenu(e.key);
  };

  return (
    <Sider
      className="flex-1 bottom-0 z-10 pb-10 fixed top-16 left-0 bg-white dark:bg-gray-900 custom-scrollbar"
      collapsible
      collapsed={collapsed}
      trigger={null}
      width={230}
      style={{ overflowY: "auto", height: "calc(100vh - 64px)" }}
    >
      <div className="demo-logo-vertical px-[8px] mt-[10px]">
        <Button
          type="text"
          icon={
            collapsed ? (
              <MenuUnfoldOutlined className="dark:text-white" />
            ) : (
              <MenuFoldOutlined className="dark:text-white" />
            )
          }
          onClick={() => setCollapsed(!collapsed)}
        />
      </div>

      <Menu
        className="mt-1 bg-white dark:bg-gray-900"
        mode="inline"
        defaultSelectedKeys={["home"]}
        onClick={handleMenuClick}
        // style={{
        //   overflowY: "auto",
        //   height: "calc(100vh - 80px)",
        // }}
        inlineIndent={10}
        selectedKeys={[selectedMenu]}
        items={[

          {
            key: "home",
            icon: <HomeOutlined className="dark:!text-white" />,
            label: (
              <span className="text-black dark:text-white">Home</span>
            ),
          },

          // {
          //   key: "infraScanning",
          //   icon: <FaServer className="!text-black dark:!text-white" />,
          //   label: (
          //     <span className="text-black dark:text-white">Infra Scan</span>
          //   ),
          //   children: [
          //     {
          //       key: "home",
          //       icon: <HomeOutlined className="dark:!text-white" />,
          //       label: <span className="dark:text-white">Home</span>,
          //     },
          //     {
          //       key: "basic",
          //       icon: <FaSearch className="dark:!text-white" />,
          //       label: <span className="dark:text-white">Basic Scan</span>,
          //       children: [
          //         {
          //           key: "summary",
          //           icon: <TbReportAnalytics className="dark:!text-white" />,
          //           label: <span className="dark:text-white">Summary</span>,
          //         },
          //         {
          //           key: "findings",
          //           icon: <FileSearchOutlined className="dark:!text-white" />,
          //           label: <span className="dark:text-white">Findings</span>,
          //         },
          //       ],
          //     },

          //     // ---------------- ADVANCED ----------------
          //     {
          //       key: "advanced",
          //       icon: <SecurityScanOutlined className="dark:!text-white" />,
          //       label: (
          //         <span className="dark:text-white flex items-center">
          //           Advanced Scan
          //           <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
          //             PRO
          //           </span>
          //         </span>
          //       ),
          //       children: [
          //         {
          //           key: "threatdetect",
          //           icon: <FaShieldAlt className="dark:!text-white" />,
          //           label: (
          //             <span className="dark:text-white">Threat Detection</span>
          //           ),
          //         },
          //       ],
          //     },

          //     // ---------------- FRAMEWORKS SECTION ----------------
          //     {
          //       key: "frameworks",
          //       icon: <RiShieldCheckLine className="dark:!text-white" />,
          //       label: (
          //         <span className="dark:text-white">
          //           Frameworks
          //           <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
          //             PRO
          //           </span>
          //         </span>
          //       ),

          //       children: [
          //         {
          //           key: "awafr",
          //           icon: (
          //             <MenuIcon src="/Assets/icons/awafr.png" alt="AWS AWFR" />
          //           ),
          //           label: <span className="dark:text-white">AWS WAFR</span>,
          //         },
          //         {
          //           key: "cis",
          //           icon: (
          //             <MenuIcon
          //               src="/Assets/icons/cis.jpg"
          //               alt="CIS Compliance"
          //             />
          //           ),
          //           label: (
          //             <span className="dark:text-white">CIS Compliance</span>
          //           ),
          //         },
          //         {
          //           key: "iso",
          //           icon: (
          //             <MenuIcon src="/Assets/icons/iso42001.jpg" alt="ISO 42001" />
          //           ),
          //           label: <span className="dark:text-white">ISO 42001</span>,
          //         },
          //         // {
          //         //   key: "nist",
          //         //   icon: <MenuIcon src="/Assets/icons/nist.png" alt="NIST" />,
          //         //   label: <span className="dark:text-white">NIST</span>,
          //         // },
          //       ],
          //     },
          //   ],
          // },

          {
            key: "aws",
            icon: <FaAws className="!text-black dark:!text-white" />,
            label: (
              <span className="text-black dark:text-white">AWS</span>
            ),
            children: [
              // {
              //   key: "home",
              //   icon: <HomeOutlined className="dark:!text-white" />,
              //   label: <span className="dark:text-white">Home</span>,
              // },
              {
                key: "aws-basic",
                icon: <FaSearch className="dark:!text-white" />,
                label: <span className="dark:text-white">Basic Scan</span>,
                children: [
                  {
                    key: "aws-summary",
                    icon: <TbReportAnalytics className="dark:!text-white" />,
                    label: <span className="dark:text-white">Summary</span>,
                  },
                  {
                    key: "aws-findings",
                    icon: <FileSearchOutlined className="dark:!text-white" />,
                    label: <span className="dark:text-white">Findings</span>,
                  },
                ],
              },

              // ---------------- ADVANCED ----------------
              {
                key: "aws-advanced",
                icon: <SecurityScanOutlined className="dark:!text-white" />,
                label: (
                  <span className="dark:text-white flex items-center">
                    Advanced Scan
                    <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
                      PRO
                    </span>
                  </span>
                ),
                children: [
                  {
                    key: "aws-threatdetect",
                    icon: <FaShieldAlt className="dark:!text-white" />,
                    label: (
                      <span className="dark:text-white">Threat Detection</span>
                    ),
                  },
                ],
              },

              // ---------------- FRAMEWORKS SECTION ----------------
              {
                key: "aws-frameworks",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: (
                  <span className="dark:text-white">
                    Frameworks
                    <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
                      PRO
                    </span>
                  </span>
                ),

                children: [
                  {
                    key: "aws-awafr",
                    icon: (
                      <MenuIcon src="/Assets/icons/awafr.png" alt="AWS AWFR" />
                    ),
                    label: <span className="dark:text-white">AWS WAFR</span>,
                  },
                  {
                    key: "aws-cis",
                    icon: (
                      <MenuIcon
                        src="/Assets/icons/cis.jpg"
                        alt="CIS Compliance"
                      />
                    ),
                    label: (
                      <span className="dark:text-white">CIS Compliance</span>
                    ),
                  },
                  {
                    key: "aws-iso",
                    icon: (
                      <MenuIcon src="/Assets/icons/iso42001.jpg" alt="ISO 42001" />
                    ),
                    label: <span className="dark:text-white">ISO 42001</span>,
                  },
                  // {
                  //   key: "nist",
                  //   icon: <MenuIcon src="/Assets/icons/nist.png" alt="NIST" />,
                  //   label: <span className="dark:text-white">NIST</span>,
                  // },
                ],
              },
            ],
          },


          // {
          //   key: "aws",
          //   icon: <FaAws  className="!text-black dark:!text-white" />,
          //   label: (
          //     <span className="text-black dark:text-white">AWS</span>
          //   ),
          //   children: [
          //     {
          //       key: "aws-home",
          //       icon: <HomeOutlined className="dark:!text-white" />,
          //       label: <span className="dark:text-white">Home</span>,
          //     },
          //     {
          //       key: "aws-basic",
          //       icon: <FaSearch className="dark:!text-white" />,
          //       label: <span className="dark:text-white">Basic Scan</span>,
          //       children: [
          //         {
          //           key: "aws-summary",
          //           icon: <TbReportAnalytics className="dark:!text-white" />,
          //           label: <span className="dark:text-white">Summary</span>,
          //         },
          //         {
          //           key: "aws-findings",
          //           icon: <FileSearchOutlined className="dark:!text-white" />,
          //           label: <span className="dark:text-white">Findings</span>,
          //         },
          //       ],
          //     },

          //     // ---------------- ADVANCED ----------------
          //     {
          //       key: "aws-advanced",
          //       icon: <SecurityScanOutlined className="dark:!text-white" />,
          //       label: (
          //         <span className="dark:text-white flex items-center">
          //           Advanced Scan
          //           <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
          //             PRO
          //           </span>
          //         </span>
          //       ),
          //       children: [
          //         {
          //           key: "aws-threatdetect",
          //           icon: <FaShieldAlt className="dark:!text-white" />,
          //           label: (
          //             <span className="dark:text-white">Threat Detection</span>
          //           ),
          //         },
          //       ],
          //     },

          //     // ---------------- FRAMEWORKS SECTION ----------------
          //     {
          //       key: "aws-frameworks",
          //       icon: <RiShieldCheckLine className="dark:!text-white" />,
          //       label: (
          //         <span className="dark:text-white">
          //           Frameworks
          //           <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
          //             PRO
          //           </span>
          //         </span>
          //       ),

          //       children: [
          //         {
          //           key: "aws-awafr",
          //           icon: (
          //             <MenuIcon src="/Assets/icons/awafr.png" alt="AWS AWFR" />
          //           ),
          //           label: <span className="dark:text-white">AWS WAFR</span>,
          //         },
          //         {
          //           key: "aws-cis",
          //           icon: (
          //             <MenuIcon
          //               src="/Assets/icons/cis.jpg"
          //               alt="CIS Compliance"
          //             />
          //           ),
          //           label: (
          //             <span className="dark:text-white">CIS Compliance</span>
          //           ),
          //         },
          //         {
          //           key: "aws-iso",
          //           icon: (
          //             <MenuIcon src="/Assets/icons/iso42001.jpg" alt="ISO 42001" />
          //           ),
          //           label: <span className="dark:text-white">ISO 42001</span>,
          //         },
          //         {
          //           key: "aws-owasp",
          //           icon: (
          //             <MenuIcon src="/Assets/icons/owasp.png" alt="OWASP" />
          //           ),
          //           label: <span className="dark:text-white">OWASP</span>,
          //         },
                  
          //         // {
          //         //   key: "nist",
          //         //   icon: <MenuIcon src="/Assets/icons/nist.png" alt="NIST" />,
          //         //   label: <span className="dark:text-white">NIST</span>,
          //         // },
          //       ],
          //     },
          //   ],
          // },

          {
            key: "az",
            icon: <VscAzure className="!text-black dark:!text-white" />,
            label: (
              <span className="text-black dark:text-white">Microsoft Azure</span>
            ),
            children: [
              // {
              //   key: "az-home",
              //   icon: <HomeOutlined className="dark:!text-white" />,
              //   label: <span className="dark:text-white">Home</span>,
              // },
              {
                key: "az-basic",
                icon: <FaSearch className="dark:!text-white" />,
                label: <span className="dark:text-white">Basic Scan</span>,
                children: [
                  {
                    key: "az-summary",
                    icon: <TbReportAnalytics className="dark:!text-white" />,
                    label: <span className="dark:text-white">Summary</span>,
                  },
                  {
                    key: "az-findings",
                    icon: <FileSearchOutlined className="dark:!text-white" />,
                    label: <span className="dark:text-white">Findings</span>,
                  },
                ],
              },

              // ---------------- ADVANCED ----------------
              {
                key: "az-advanced",
                icon: <SecurityScanOutlined className="dark:!text-white" />,
                label: (
                  <span className="dark:text-white flex items-center">
                    Advanced Scan
                    <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
                      PRO
                    </span>
                  </span>
                ),
                children: [
                  {
                    key: "az-threatdetect",
                    icon: <FaShieldAlt className="dark:!text-white" />,
                    label: (
                      <span className="dark:text-white">Threat Detection</span>
                    ),
                  },
                ],
              },

              // ---------------- FRAMEWORKS SECTION ----------------
              {
                key: "az-frameworks",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: (
                  <span className="dark:text-white">
                    Frameworks
                    <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
                      PRO
                    </span>
                  </span>
                ),

                children: [
                  {
                    key: "az-awafr",
                    icon: (
                      <MenuIcon src="/Assets/icons/awafr.png" alt="AWS AWFR" />
                    ),
                    label: <span className="dark:text-white">AWS WAFR</span>,
                  },
                  {
                    key: "az-cis",
                    icon: (
                      <MenuIcon
                        src="/Assets/icons/cis.jpg"
                        alt="CIS Compliance"
                      />
                    ),
                    label: (
                      <span className="dark:text-white">CIS Compliance</span>
                    ),
                  },
                  {
                    key: "az-iso",
                    icon: (
                      <MenuIcon src="/Assets/icons/iso42001.jpg" alt="ISO 42001" />
                    ),
                    label: <span className="dark:text-white">ISO 42001</span>,
                  },
                  {
                    key: "az-owasp",
                    icon: (
                      <MenuIcon src="/Assets/icons/owasp.png" alt="OWASP" />
                    ),
                    label: <span className="dark:text-white">OWASP</span>,
                  },
                  
                  // {
                  //   key: "nist",
                  //   icon: <MenuIcon src="/Assets/icons/nist.png" alt="NIST" />,
                  //   label: <span className="dark:text-white">NIST</span>,
                  // },
                ],
              },
            ],
          },

          {
            key: "gcp",
            icon: <BiLogoGoogleCloud className="!text-black dark:!text-white" />,
            label: (
              <span className="text-black dark:text-white">GCP</span>
            ),
            children: [
              // {
              //   key: "gcp-home",
              //   icon: <HomeOutlined className="dark:!text-white" />,
              //   label: <span className="dark:text-white">Home</span>,
              // },
              {
                key: "gcp-basic",
                icon: <FaSearch className="dark:!text-white" />,
                label: <span className="dark:text-white">Basic Scan</span>,
                children: [
                  {
                    key: "gcp-summary",
                    icon: <TbReportAnalytics className="dark:!text-white" />,
                    label: <span className="dark:text-white">Summary</span>,
                  },
                  {
                    key: "gcp-findings",
                    icon: <FileSearchOutlined className="dark:!text-white" />,
                    label: <span className="dark:text-white">Findings</span>,
                  },
                ],
              },

              // ---------------- ADVANCED ----------------
              {
                key: "gcp-advanced",
                icon: <SecurityScanOutlined className="dark:!text-white" />,
                label: (
                  <span className="dark:text-white flex items-center">
                    Advanced Scan
                    <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
                      PRO
                    </span>
                  </span>
                ),
                children: [
                  {
                    key: "gcp-threatdetect",
                    icon: <FaShieldAlt className="dark:!text-white" />,
                    label: (
                      <span className="dark:text-white">Threat Detection</span>
                    ),
                  },
                ],
              },

              // ---------------- FRAMEWORKS SECTION ----------------
              {
                key: "gcp-frameworks",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: (
                  <span className="dark:text-white">
                    Frameworks
                    <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
                      PRO
                    </span>
                  </span>
                ),

                children: [
                  {
                    key: "gcp-awafr",
                    icon: (
                      <MenuIcon src="/Assets/icons/awafr.png" alt="AWS AWFR" />
                    ),
                    label: <span className="dark:text-white">AWS WAFR</span>,
                  },
                  {
                    key: "gcp-cis",
                    icon: (
                      <MenuIcon
                        src="/Assets/icons/cis.jpg"
                        alt="CIS Compliance"
                      />
                    ),
                    label: (
                      <span className="dark:text-white">CIS Compliance</span>
                    ),
                  },
                  {
                    key: "gcp-iso",
                    icon: (
                      <MenuIcon src="/Assets/icons/iso42001.jpg" alt="ISO 42001" />
                    ),
                    label: <span className="dark:text-white">ISO 42001</span>,
                  }
                  
                  // {
                  //   key: "nist",
                  //   icon: <MenuIcon src="/Assets/icons/nist.png" alt="NIST" />,
                  //   label: <span className="dark:text-white">NIST</span>,
                  // },
                ],
              },
            ],
          },









          // ---------------- EKS ----------------
          {
            key: "EKSScanning",
            icon: <SiKubernetes className="!text-black dark:!text-white" />,
            label: (
              <span className="text-black dark:text-white flex items-center">
                EKS Scan
                <span className="ml-2 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-indigo-700 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
                  PRO
                </span>
              </span>
            ),
            children: [
              {
                key: "ekshome",
                icon: <HomeOutlined className="dark:!text-white" />,
                label: <span className="dark:text-white">Home</span>,
              },
              {
                key: "clusters",
                icon: <AiOutlineKubernetes className="dark:!text-white" />,
                label: <span className="dark:text-white">Clusters</span>,
              },
              {
                key: "results",
                icon: <FaChartBar className="dark:!text-white" />,
                label: <span className="dark:text-white">Reports</span>,
              },
            ],
          },

          // ---------------- SECURITY DASHBOARD (IP Protected) ----------------
          ipAllowed && {
            key: "securityDashboard",
            icon: <RiDashboard3Line className="!text-black dark:!text-white" />,
            label: (
              <span className="text-black dark:text-white">
                Security Dashboard
              </span>
            ),
            children: [
              {
                key: "site24x7",
                icon: <BiPulse className="dark:!text-white" />,
                label: (
                  <span className="dark:text-white">Site24x7 Dashboard</span>
                ),
              },
            ],
          },
        ].filter(Boolean)}
      />
    </Sider>
  );
}
