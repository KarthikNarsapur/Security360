import {
  FileSearchOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  HomeOutlined,
  SecurityScanOutlined,
  BarsOutlined,
  BookOutlined,
  BankOutlined,
} from "@ant-design/icons";
import { Layout, Menu, Button, Tooltip } from "antd";
import { useNavigate } from "react-router-dom";
import { AiOutlineKubernetes } from "react-icons/ai";
import { SiKubernetes } from "react-icons/si";
import { FaChartBar, FaShieldAlt, FaSearch, FaAws, FaIndustry } from "react-icons/fa";
import { VscAzure } from "react-icons/vsc";
import { BiLogoGoogleCloud } from "react-icons/bi";
import "./Scrollbar.css";
import { TbReportAnalytics } from "react-icons/tb";
import { RiDashboard3Line, RiShieldCheckLine } from "react-icons/ri";
import { useEffect, useState, useCallback, useRef } from "react";
import { BiPulse } from "react-icons/bi";
import { MenuIcon } from "./Utils";

const { Sider } = Layout;

const MIN_WIDTH = 180;
const MAX_WIDTH = 420;
const DEFAULT_WIDTH = 260;

export default function SidebarComponent({
  collapsed,
  setCollapsed,
  selectedMenu,
  setSelectedMenu,
  siderWidth,
  setSiderWidth,
}) {
  const navigate = useNavigate();
  const [ipAllowed, setIpAllowed] = useState(false);
  const isResizing = useRef(false);
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

  // ── Drag-to-resize handlers ─────────────────────────────────────────────────
  const handleMouseDown = useCallback((e) => {
    e.preventDefault();
    isResizing.current = true;
    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";
  }, []);

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!isResizing.current) return;
      const newWidth = Math.min(MAX_WIDTH, Math.max(MIN_WIDTH, e.clientX));
      setSiderWidth(newWidth);
    };
    const handleMouseUp = () => {
      isResizing.current = false;
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.addEventListener("mousemove", handleMouseMove);
    document.addEventListener("mouseup", handleMouseUp);
    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
    };
  }, []);

  const handleMenuClick = (e) => {
    setSelectedMenu(e.key);
  };

  const currentWidth = collapsed ? 80 : siderWidth;

  // Helper to wrap label with tooltip
  const withTooltip = (text) => (
    <Tooltip title={text} placement="right" mouseEnterDelay={0.4}>
      <span className="dark:text-white">{text}</span>
    </Tooltip>
  );

  return (
    <>
      {/* Drag handle — fixed, outside Sider scroll context */}
      {!collapsed && (
        <div
          onMouseDown={handleMouseDown}
          style={{ left: currentWidth - 3, top: 64 }}
          className="fixed w-1.5 h-[calc(100vh-64px)] cursor-col-resize hover:bg-indigo-400/40 transition-colors z-50"
        />
      )}
      <Sider
        className="flex-1 bottom-0 z-10 pb-10 fixed top-16 left-0 bg-white dark:bg-gray-900 custom-scrollbar"
        collapsible
        collapsed={collapsed}
        trigger={null}
        width={currentWidth}
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

          // ---------------- INDUSTRY-BASED ----------------
          {
            key: "industry",
            icon: <FaIndustry className="!text-black dark:!text-white" />,
            label: (
              <span className="text-black dark:text-white">Industry-Based</span>
            ),
            children: [
              {
                key: "industry-healthcare",
                label: <span className="dark:text-white">🏥 Healthcare</span>,
              },
              {
                key: "industry-finance",
                label: <span className="dark:text-white">💳 Finance</span>,
              },
              {
                key: "industry-saas",
                label: <span className="dark:text-white">☁️ SaaS</span>,
              },
              {
                key: "industry-government",
                label: <span className="dark:text-white">🏛 Government</span>,
              },
              {
                key: "industry-ecommerce",
                label: <span className="dark:text-white">🛒 E-commerce</span>,
              },
            ],
          },

          // ---------------- COMPLIANCE ----------------
          {
            key: "compliance",
            icon: <BookOutlined className="!text-black dark:!text-white" />,
            label: (
              <span className="text-black dark:text-white">Compliance</span>
            ),
            children: [
              {
                key: "compliance-gdpr",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Data Protection (GDPR)"),
              },
              {
                key: "compliance-pcidss",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Payment Security (PCI DSS)"),
              },
              {
                key: "compliance-hipaa",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Healthcare Security (HIPAA)"),
              },
              {
                key: "compliance-soc2",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Enterprise Security (SOC 2)"),
              },
              {
                key: "compliance-fedramp",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Government Security (FedRAMP)"),
              },
              {
                key: "compliance-wafr",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Cloud Best Practices (AWS Well-Architected)"),
              },
              {
                key: "compliance-cis",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Security Baseline (CIS Benchmark)"),
              },
              {
                key: "compliance-nist",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Risk Framework (NIST CSF)"),
              },
              {
                key: "compliance-dpdp",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Data Protection (DPDP Act)"),
              },
              {
                key: "compliance-rbi",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Banking Security (RBI CSF)"),
              },
              {
                key: "compliance-sebi",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Market Security (SEBI CSCRF)"),
              },
              {
                key: "compliance-ndhm",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Digital Health (NDHM)"),
              },
              {
                key: "compliance-ehr",
                icon: <RiShieldCheckLine className="dark:!text-white" />,
                label: withTooltip("Health Records (EHR Standards)"),
              },
            ],
          },
        ].filter(Boolean)}
      />
    </Sider>
    </>
  );
}
