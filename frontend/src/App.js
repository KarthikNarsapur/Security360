import { useEffect, useState } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
} from "react-router-dom";
import Login from "./components/Auth/Login";
import Signup from "./components/Auth/Signup";
import "./index.css";
import DB from "./components/Dashboard";
import VerificationCode from "./components/Auth/VerificationCode";
import Header from "./components/Header";
import WelcomePage from "./components/WelcomePage";
import "./index.css";
import ForgotPassword from "./components/Auth/ForgotPassword";
import ResetPassword from "./components/Auth/ResetPassword";
import ProfilePage from "./components/ProfilePage";
import { ConfigProvider, theme, Modal } from "antd";
import ContactForm from "./components/ContactUsPage";
import AccountsPage from "./components/AccountsPage";
import RBISummary from "./components/Framework/RBI/RBISummary";
import SEBISummary from "./components/Framework/SEBI/SEBISummary";
import PCIDSSSummary from "./components/Framework/PCIDSS/PCIDSSSummary";
import OWASPSummary from "./components/Framework/OWASP/OWASPSummary";

const { darkAlgorithm, defaultAlgorithm } = theme;

function App() {
  const [darkMode, setDarkMode] = useState(false);
  const [modal, contextHolder] = Modal.useModal();

  useEffect(() => {
    const savedDarkMode = localStorage.getItem("darkMode") === "true";
    setDarkMode(savedDarkMode);
  }, []);

  const toggleDarkMode = () => {
    const newDarkMode = !darkMode;
    setDarkMode(newDarkMode);
    localStorage.setItem("darkMode", newDarkMode);
  };

  const customLightThemeTokens = {
    drawerBorderColor: "rgb(146, 152, 161)",
  };

  const customDarkThemeTokens = {
    colorBgElevated: "#0f172aF2",
    drawerBorderColor: "rgb(51, 65, 85)",
  };

  return (
    <>
      <ConfigProvider
        theme={{
          algorithm: darkMode ? darkAlgorithm : defaultAlgorithm,
          token: darkMode ? customDarkThemeTokens : customLightThemeTokens,
        }}
      >
        <div className={darkMode ? "dark" : ""}>
          <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 transition-colors duration-300">
            <Router>
              <Header darkMode={darkMode} toggleDarkMode={toggleDarkMode} />
              <div className="pt-16">
                <Routes>
                  <Route path="/" element={<WelcomePage />} />
                  <Route path="/dashboard" element={<DB />} />
                  <Route path="/login" element={<Login />} />
                  <Route path="/signup" element={<Signup />} />
                  <Route path="/verification" element={<VerificationCode />} />
                  <Route path="/forgot" element={<ForgotPassword />} />
                  <Route path="/reset" element={<ResetPassword />} />
                  <Route path="/profile" element={<ProfilePage />} />
                  <Route path="/contact-us" element={<ContactForm />} />
                  <Route path="/accounts" element={<AccountsPage />} />
                  <Route path="/rbi" element={<RBISummary />} />
                  <Route path="/sebi" element={<SEBISummary />} />
                  <Route path="/pcidss" element={<PCIDSSSummary />} />
                  <Route path="/owasp" element={<OWASPSummary />} />

                  {/* Catch-all route */}
                  <Route
                    path="*"
                    element={<Navigate to="/dashboard" replace />}
                  />
                </Routes>
              </div>
            </Router>
          </div>
        </div>
        {contextHolder}
      </ConfigProvider>
    </>
  );
}

export default App;
