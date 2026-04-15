// pages/Dashboard.jsx
import React, { useState, useEffect } from "react";
import { TbMessageChatbotFilled } from "react-icons/tb";
import { Layout, theme, Button } from "antd";
import {
  AppstoreOutlined,
  FileSearchOutlined,
  HomeOutlined,
} from "@ant-design/icons";

import "./Dashboard.css";
import SummaryComponent from "./SummaryComponent";
import FindingsComponent from "./FindingsComponent";
import SidebarComponent from "./SidebarComponent";
import OUComponent from "./OuComponent";
import HomePage from "./Homepage";
import { OrbitProgress } from "react-loading-indicators";
import ThreatDetection from "./Threat_Detection/ThreatDetection";
import Chatbot from "./Chatbot";
import Cookies from "js-cookie";
import { notifyError, notifyInfo } from "./Notification";
import { useNavigate } from "react-router-dom";
import CisDashboard from "./CIS/CisDashboard";
import ClusterDisplay from "./UI/ClusterDisplay";
import ClusterFindings from "./UI/ClusterFindings";
import EKSHomePage from "./EKSHomePage";
import { fetchUserDetails } from "./Utils";
import ISODashboard from "./ISO/ISODashboard";
// import NISTDashboard from "./NIST/NISTDashboard";
import AWAFDashboard from "./AWAF/AWAFDashboard";
import Site24x7_dashboard from "./Site24x7/Site24x7_dashboard";
import OWASPSummary from "./Framework/OWASP/OWASPSummary";

const { Header, Content } = Layout;

export default function Dashboard({ modal, darkMode }) {
  const [results, setResults] = useState([]);
  const [selectedMenu, setSelectedMenu] = useState("home");
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [collapsed, setCollapsed] = useState(false);
  const [meta, setMeta] = useState({});
  // const [report, setReport] = useState([]);
  const [isReportAvailable, setIsReportAvailable] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showchatbot, setShowchatbot] = useState(false);
  const [userName, setUserName] = useState("");
  const [fullName, setFullName] = useState("");
  const [accountDetails, setAccountDetails] = useState([]);
  const [eksAccountDetails, setEksAccountDetails] = useState([]);
  const [isSampleReport, setIsSampleReport] = useState(false);

  const [prevReportAvailable, setPrevReportAvailable] = useState(true);
  const [securityServicesScanResults, setSecurityServicesScanResults] =
    useState([{}]);
  const [globalServicesScanResults, setGlobalServicesScanResults] = useState(
    {},
  );
  const [clusters, setClusters] = useState([
    {
      cluster_name: "common-ap-south-1-test-eks",
      status: "ACTIVE",
      version: "1.32",
      endpoint:
        "https://2C823F2DCB7A2C743C8E390C603A86C7.gr7.ap-south-1.eks.amazonaws.com",
      created_at: "2025-04-28 06:00:15.470000+00:00",
      region: "ap-south-1",
    },
  ]);
  const [isSummaryScanSampleReport, setIsSummaryScanSampleReport] =
    useState(false);

  //site24x7 dashboard

  const ROTATION_SECONDS = 60;
  const [dashboards, setDashboards] = useState([]);
  const [currentDashboard, setCurrentDashboard] = useState(null);
  const [remainingSeconds, setRemainingSeconds] = useState(ROTATION_SECONDS);
  const [isAdmin, setIsAdmin] = useState(false);

  const navigate = useNavigate();

  const [messages, setMessages] = useState([
    { sender: "bot", text: "Hello! How can I assist you today?" },
  ]);

  const {
    token: { colorBgContainer, borderRadiusLG },
  } = theme.useToken();

  useEffect(() => {
    const getUserData = async () => {
      const result = await fetchUserDetails({ navigate });
      if (result.status == "ok") {
        setUserName(result.userName);
        setFullName(result.fullName);
        setAccountDetails(result.accountDetails);
        setEksAccountDetails(result.eksAccountDetails);
        result.isAdmin && setIsAdmin(result.isAdmin);
      }
    };
    getUserData();
  }, []);

  return (
    <div>
      <Layout
        hasSider
        className="h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950"
      >
        <SidebarComponent
          collapsed={collapsed}
          setCollapsed={setCollapsed}
          setSelectedMenu={setSelectedMenu}
          selectedMenu={selectedMenu}
        />

        <Layout
          style={{
            marginLeft: collapsed ? "80px" : "200px",
            transition: "margin-left 0.3s",
          }}
        >
          <Content className="bg-gray-100 dark:bg-gray-500">
            <div className="bg-gray-100 dark:bg-gray-500">
              {selectedMenu === "home" && (
                <HomePage
                  userName={userName}
                  fullName={fullName}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}

              {selectedMenu === "summary" && (
                <SummaryComponent
                  setSelectedMenu={setSelectedMenu}
                  results={results}
                  setResults={setResults}
                  meta={meta}
                  setMeta={setMeta}
                  isReportAvailable={isReportAvailable}
                  setIsReportAvailable={setIsReportAvailable}
                  accountDetails={accountDetails}
                  prevReportAvailable={prevReportAvailable}
                  setPrevReportAvailable={setPrevReportAvailable}
                  securityServicesScanResults={securityServicesScanResults}
                  setSecurityServicesScanResults={
                    setSecurityServicesScanResults
                  }
                  globalServicesScanResults={globalServicesScanResults}
                  setGlobalServicesScanResults={setGlobalServicesScanResults}
                  modal={modal}
                  darkMode={darkMode}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                  isSummaryScanSampleReport={isSummaryScanSampleReport}
                  setIsSummaryScanSampleReport={setIsSummaryScanSampleReport}
                  isSampleReport={isSampleReport}
                  setIsSampleReport={setIsSampleReport}
                />
              )}

              {selectedMenu == "findings" && (
                <FindingsComponent
                  findings={results}
                  selectedFinding={selectedFinding}
                  onSelect={setSelectedFinding}
                  onClose={() => setSelectedFinding(null)}
                  meta={meta}
                  fullName={fullName}
                  securityServicesScanResults={securityServicesScanResults}
                  setSecurityServicesScanResults={
                    setSecurityServicesScanResults
                  }
                  globalServicesScanResults={globalServicesScanResults}
                  modal={modal}
                  darkMode={darkMode}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                  isSummaryScanSampleReport={isSummaryScanSampleReport}
                  setIsSummaryScanSampleReport={setIsSummaryScanSampleReport}
                  isSampleReport={isSampleReport}
                  setIsSampleReport={setIsSampleReport}
                />
              )}

              {selectedMenu === "threatdetect" && (
                <ThreatDetection
                  accountDetails={accountDetails}
                  modal={modal}
                  darkMode={darkMode}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}
              {selectedMenu === "cis" && (
                <CisDashboard
                  accountDetails={accountDetails}
                  modal={modal}
                  darkMode={darkMode}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}
              {selectedMenu === "iso" && (
                <ISODashboard
                  accountDetails={accountDetails}
                  modal={modal}
                  darkMode={darkMode}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}
              {/* {selectedMenu === "nist" && (
                <NISTDashboard
                  accountDetails={accountDetails}
                  modal={modal}
                  darkMode={darkMode}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )} */}
              {selectedMenu === "owasp" && (
                <OWASPSummary
                  accountDetails={accountDetails}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}
              {selectedMenu === "awafr" && (
                <AWAFDashboard
                  accountDetails={accountDetails}
                  modal={modal}
                  darkMode={darkMode}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}

              {selectedMenu === "clusters" && (
                <ClusterDisplay
                  accountDetails={accountDetails}
                  modal={modal}
                  darkMode={darkMode}
                  clusters={clusters}
                  setClusters={setClusters}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}
              {selectedMenu === "results" && (
                <ClusterFindings
                  accountDetails={accountDetails}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}
              {selectedMenu === "ekshome" && (
                <EKSHomePage
                  accountDetails={accountDetails}
                  modal={modal}
                  darkMode={darkMode}
                  userName={userName}
                  fullName={fullName}
                  setUserName={setUserName}
                  setFullName={setFullName}
                  setAccountDetails={setAccountDetails}
                  setEksAccountDetails={setEksAccountDetails}
                />
              )}
              {selectedMenu === "site24x7" && (
                <Site24x7_dashboard
                  ROTATION_SECONDS={ROTATION_SECONDS}
                  dashboards={dashboards}
                  setDashboards={setDashboards}
                  currentDashboard={currentDashboard}
                  setCurrentDashboard={setCurrentDashboard}
                  remainingSeconds={remainingSeconds}
                  setRemainingSeconds={setRemainingSeconds}
                  isAdmin={isAdmin}
                />
              )}
            </div>
            <div className="fixed bottom-0 right-0 m-7">
              <Button
                className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:!from-indigo-700 hover:!to-indigo-800 hover:!text-white text-white text-xl font-semibold dark:bg-gray-300 dark:border-gray-300 dark:hover:!bg-gray-100 border-0 p-5 transition-all duration-200 hover:scale-105 rounded-xl"
                onClick={() => setShowchatbot((prev) => !prev)}
              >
                <TbMessageChatbotFilled />
              </Button>
            </div>
          </Content>
        </Layout>
        {showchatbot && (
          <Chatbot
            messages={messages}
            setMessages={setMessages}
            onClose={() => setShowchatbot(false)}
          />
        )}
      </Layout>
    </div>
  );
}
