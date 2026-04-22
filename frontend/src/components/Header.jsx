import { useEffect, useState } from "react";
import { Button } from "antd";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { LuSunMedium } from "react-icons/lu";
import { IoMoonOutline } from "react-icons/io5";
import { Dropdown, Avatar, Space } from "antd";
import { UserOutlined } from "@ant-design/icons";
import { PiKeyBold } from "react-icons/pi";
import { IoLogOutOutline } from "react-icons/io5";
import { FaRegUser } from "react-icons/fa6";
import Cookies from "js-cookie";
import { notifyError } from "./Notification";

function Header({ darkMode, toggleDarkMode }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [isLogedIn, setIslogedIn] = useState(false);

  const handleGetStarted = (path) => {
    navigate(path);
  };

  const imageClick = (image_type) => {
    if (image_type === "cloudthat") {
      window.open("https://www.cloudthat.com", "_blank");
    } else {
      navigate("/");
    }
  };

  const handleLogout = () => {
    try {
      Cookies.remove("access_token");
      Cookies.remove("id_token");
      Cookies.remove("refresh_token");
      localStorage.removeItem("username");
      localStorage.removeItem("full_name");
      localStorage.removeItem("account_details");
      localStorage.removeItem("eks_account_details");

      window.location.href = "/login";
    } catch (error) {
      notifyError("Error in log out");
    }
  };

  const checkIsLogedIn = async () => {
    try {
      if (Cookies.get("access_token")) {
        setIslogedIn(true);
      }
    } catch (err) {
      console.log("error: ", err);
    }
  };

  useEffect(() => {
    checkIsLogedIn();
  }, [location.pathname]);

  const items = [
    {
      label: (
        <Link
          to="/profile"
          className="flex items-center gap-3 p-3 rounded-lg transition-colors"
        >
          <FaRegUser className="text-lg text-indigo-600 dark:text-indigo-400" />
          <span className="text-slate-700 dark:text-slate-200">
            View Profile
          </span>
        </Link>
      ),
      key: "0",
    },
    {
      type: "divider",
    },
    {
      label: (
        <div
          onClick={() => handleLogout()}
          className="flex items-center gap-3 p-3 rounded-lg transition-colors cursor-pointer"
        >
          <IoLogOutOutline className="text-lg text-red-600 dark:text-red-400" />
          <span className="text-red-600 dark:text-red-400">Logout</span>
        </div>
      ),
      key: "3",
    },
  ];

  const isAuthPage =
    location.pathname === "/login" ||
    location.pathname === "/signup" ||
    // location.pathname === "/dashboard" ||
    // location.pathname === "/profile" ||
    location.pathname === "/forgot" ||
    location.pathname === "/verification";

  const isUser =
    location.pathname === "/login" ||
    location.pathname === "/signup" ||
    location.pathname === "/forgot" ||
    location.pathname === "/reset" ||
    location.pathname === "/verification" ||
    location.pathname === "/";

  const isContactUsPage = location.pathname === "/contact-us";

  return (
    <header className="fixed top-0 left-0 w-full z-50 bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg border-b border-indigo-100 dark:border-slate-700 shadow-lg shadow-indigo-500/5">
      <div className="flex justify-between items-center px-6 py-3">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-3">
            <img
              src="logo.png"
              className="cursor-pointer hover:scale-105 transition-transform duration-200"
              onClick={() => imageClick("Security360")}
              width={60}
              alt="Logo"
            />
            {/* <div className="h-8 w-px bg-gradient-to-b from-indigo-200 to-indigo-400 dark:from-slate-600 dark:to-slate-400"></div> */}
            {/* <img
              src="SecOpsLogo.png"
              className="cursor-pointer hover:scale-105 transition-transform duration-200 block"
              onClick={() => imageClick("Security360")}
              width={60}
              alt="Security360 Logo"
            /> */}
          </div>
        </div>

        <div className="flex items-center gap-4">
          {!isContactUsPage && (
            <Button
              onClick={() => navigate("contact-us")}
              className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
            >
              Contact Us
            </Button>
          )}

          {!isAuthPage && (
            <>
              {isLogedIn ? (
                <>
                  {/* Show Dashboard button only if NOT on dashboard page */}
                  {location.pathname !== "/dashboard" && (
                    <Button
                      onClick={() => handleGetStarted("/dashboard")}
                      className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                    >
                      Dashboard
                    </Button>
                  )}

                  {/* Accounts button */}
                  {location.pathname !== "/accounts" && (
                    <Button
                      onClick={() => handleGetStarted("/accounts")}
                      className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                    >
                      Accounts
                    </Button>
                  )}
                </>
              ) : (
                <>
                  <Button
                    onClick={() => handleGetStarted("/login")}
                    className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                  >
                    Login
                  </Button>
                  <Button
                    onClick={() => handleGetStarted("/signup")}
                    className="!bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-700 hover:to-emerald-800 text-white hover:!text-white border-0 font-semibold px-6 py-2 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                  >
                    Signup
                  </Button>
                </>
              )}
            </>
          )}

          {/* toogle theme button */}
          <button
            onClick={toggleDarkMode}
            className="p-2.5 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 dark:from-slate-700 dark:to-slate-800 dark:hover:from-slate-600 dark:hover:to-slate-700 text-white rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
          >
            {darkMode ? (
              <LuSunMedium className="w-4 h-4" />
            ) : (
              <IoMoonOutline className="w-4 h-4" />
            )}
          </button>

          {!isUser && (
            <Dropdown
              menu={{ items }}
              trigger={["click"]}
              placement="bottomRight"
              overlayClassName="header-dropdown"
            >
              <Space>
                <Avatar
                  className="bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white cursor-pointer shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                  icon={<UserOutlined />}
                  size="large"
                />
              </Space>
            </Dropdown>
          )}
        </div>
      </div>
    </header>
  );
}

export default Header;
