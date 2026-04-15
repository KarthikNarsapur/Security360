import React, { useState, useEffect } from "react";
import {
  FullscreenOutlined,
  FullscreenExitOutlined,
  LeftOutlined,
  RightOutlined,
} from "@ant-design/icons";
import { Tooltip, Button } from "antd";
import { notifyError, notifySuccess } from "../Notification";
import DashboardDropdown from "../UI/DropDown/DashboardDropdown";
import TimerDropdown from "../UI/DropDown/TimerDropdown";
import AddDashboardModal from "../Site24x7/AddDashboardModal";
import Cookies from "js-cookie";

const Site24x7_dashboard = ({
  ROTATION_SECONDS,
  dashboards,
  setDashboards,
  currentDashboard,
  setCurrentDashboard,
  remainingSeconds,
  setRemainingSeconds,
  isAdmin,
}) => {
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [rotationSeconds, setRotationSeconds] = useState(ROTATION_SECONDS);
  const [showAddDashboardModal, setShowAddDashboardModal] = useState(false);
  const [savingRotation, setSavingRotation] = useState(false);
  const [savingDashboard, setSavingDashboard] = useState(false);

  const backend_url = process.env.REACT_APP_BACKEND_URL;

  // Fetch dashboards

  useEffect(() => {
    if (dashboards.length > 0) return;

    const fetchDashboards = async () => {
      try {
        const res = await fetch(`${backend_url}/api/site24x7-dashboard`);
        const data = await res.json();

        if (data.status === "error") {
          notifyError(data.error_message || "Unknown error occurred");
          return;
        }

        setDashboards(data);
        setCurrentDashboard(data[0]);
      } catch (err) {
        notifyError("Failed to load dashboards");
        console.error(err);
      }
    };

    fetchDashboards();
  }, []);

  // Fetch rotation timeout settings

  useEffect(() => {
    const fetchSettings = async () => {
      try {
        const res = await fetch(`${backend_url}/api/site24x7/settings`);
        const data = await res.json();

        if (data.status === "ok") {
          setRotationSeconds(data.settings.rotationSeconds);
          setRemainingSeconds(data.settings.rotationSeconds);
        }
      } catch (err) {
        console.error("Failed to load settings", err);
      }
    };

    fetchSettings();
  }, []);

  // Auto rotate dashboards

  useEffect(() => {
    if (!dashboards.length) return;

    const rotationInterval = setInterval(() => {
      setCurrentDashboard((prev) => {
        const index = dashboards.findIndex((d) => d.url === prev.url);
        const nextIndex = (index + 1) % dashboards.length;
        return dashboards[nextIndex];
      });

      setRemainingSeconds(rotationSeconds);
    }, rotationSeconds * 1000);

    return () => clearInterval(rotationInterval);
  }, [dashboards, rotationSeconds]);

  // Countdown timer

  useEffect(() => {
    const countdown = setInterval(() => {
      setRemainingSeconds((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);

    return () => clearInterval(countdown);
  }, []);

  // Fullscreen toggle effect

  useEffect(() => {
    document.body.style.overflow = isFullscreen ? "hidden" : "auto";

    return () => {
      document.body.style.overflow = "auto";
    };
  }, [isFullscreen]);

  // Loading state

  if (!currentDashboard) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <p className="text-lg font-semibold">Loading dashboards...</p>
      </div>
    );
  }

  const handleSaveDashboard = async (form, resetForm) => {
    const token = Cookies.get("access_token");

    try {
      setSavingDashboard(true);

      const res = await fetch(`${backend_url}/api/site24x7-dashboard/add`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(form),
      });

      const data = await res.json();

      if (data.status === "ok") {
        notifySuccess("Dashboard added successfully!");

        // Update UI list
        setDashboards((prev) => [...prev, form]);

        // Reset modal form
        resetForm();

        // Close modal
        setShowAddDashboardModal(false);
      } else {
        notifyError(data.error_message);
      }
    } catch (error) {
      console.error("Error adding dashboard:", error);
      notifyError("Something went wrong. Please try again.");
    } finally {
      setSavingDashboard(false);
    }
  };

  return (
    <div
      className={`min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 ${
        isFullscreen ? "p-0" : "p-6 pl-12"
      }`}
    >
      {/* Header  */}

      <div className="flex items-center justify-start w-full py-3">
        <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
          Site24x7 Dashboard
        </h1>

        <div className="flex items-center gap-3 ml-auto">
          {!isAdmin && (
            <p className="text-md font-semibold text-gray-700 dark:text-gray-300 mr-2">
              Select Client Dashboard:
            </p>
          )}

          {/* Dashboard Dropdown */}
          <div className={`${isAdmin ? "w-40 ml-6" : "w-80"}`}>
            <DashboardDropdown
              dashboards={dashboards}
              selectedDashboard={currentDashboard}
              onDashboardChange={(val) => {
                setCurrentDashboard(val);
                setRemainingSeconds(rotationSeconds);
              }}
            />
          </div>

          {/* Admin-only Controls */}
          {isAdmin && (
            <>
              {/* Timer Selector */}
              <div className="w-40">
                <TimerDropdown
                  rotationSeconds={rotationSeconds}
                  disabled={savingRotation}
                  onChange={async (val) => {
                    if (!isAdmin) return;

                    try {
                      setSavingRotation(true);

                      const token = Cookies.get("accessToken");

                      const response = await fetch(
                        `${backend_url}/api/site24x7/settings/update`,
                        {
                          method: "POST",
                          headers: {
                            "Content-Type": "application/json",
                            Authorization: `Bearer ${token}`,
                          },
                          body: JSON.stringify({ rotationSeconds: val }),
                        }
                      );

                      const apiResponse = await response.json();

                      if (apiResponse?.status === "ok") {
                        notifySuccess("Auto-switch time updated successfully!");
                        setRotationSeconds(val);
                        setRemainingSeconds(val);
                      } else {
                        notifyError(
                          apiResponse?.error_message ||
                            "Failed to update rotation time"
                        );
                      }
                    } catch (error) {
                      console.error("Error updating settings:", error);
                      notifyError("Something went wrong. Please try again.");
                    } finally {
                      setSavingRotation(false);
                    }
                  }}
                />
              </div>
              {/* Add Dashboard Button */}
              <button
                className="px-4 py-2 rounded-xl 
                     bg-gradient-to-r from-indigo-600 to-indigo-700 
                     hover:from-indigo-700 hover:to-indigo-800 text-white 
                     shadow-lg hover:shadow-xl transition-all hover:scale-105"
                onClick={() => setShowAddDashboardModal(true)}
                disabled={savingDashboard}
              >
                Add Dashboard
              </button>
            </>
          )}
        </div>
      </div>

      {/* Top bar */}
      <div
        className={`flex items-center justify-between w-full py-3 ${
          isFullscreen
            ? "fixed top-0 left-0 z-[9999] bg-black text-white px-6"
            : "bg-transparent"
        }`}
      >
        <div className="flex items-center gap-6">
          <p className="text-lg font-semibold">
            Active Client: {currentDashboard.clientName}
          </p>

          <p
            className={`text-md font-medium 
              ${isFullscreen ? "opacity-80" : "text-gray-600"}
              ${
                remainingSeconds < 10
                  ? "animate-pulse scale-110 font-bold transition-all duration-700"
                  : ""
              }`}
          >
            Auto-switch in {remainingSeconds}s
          </p>
        </div>

        <div className="flex items-center gap-4">
          {/* Prev Button */}
          <Tooltip title="Previous Dashboard">
            <Button
              type="text"
              onClick={() => {
                const index = dashboards.findIndex(
                  (d) => d.url === currentDashboard.url
                );
                const prevIndex =
                  (index - 1 + dashboards.length) % dashboards.length;
                setCurrentDashboard(dashboards[prevIndex]);
                setRemainingSeconds(rotationSeconds);
              }}
              className={`text-lg hover:scale-110 active:scale-95 font-bold ${
                isFullscreen ? "!text-white" : "text-black dark:!text-white"
              }`}
            >
              <LeftOutlined />
            </Button>
          </Tooltip>

          {/* Next Button */}
          <Tooltip title="Next Dashboard">
            <Button
              type="text"
              onClick={() => {
                const index = dashboards.findIndex(
                  (d) => d.url === currentDashboard.url
                );
                const nextIndex = (index + 1) % dashboards.length;
                setCurrentDashboard(dashboards[nextIndex]);
                setRemainingSeconds(rotationSeconds);
              }}
              className={`text-lg hover:scale-110 active:scale-95 font-bold ${
                isFullscreen ? "!text-white" : "text-black dark:!text-white"
              }`}
            >
              <RightOutlined />
            </Button>
          </Tooltip>

          {/* Fullscreen Toggle Button */}
          <Tooltip title={isFullscreen ? "Exit Fullscreen" : "Go Fullscreen"}>
            <Button
              type="text"
              onClick={() => setIsFullscreen(!isFullscreen)}
              className={`text-xl hover:scale-110 active:scale-95 font-bold ${
                isFullscreen ? "!text-white" : "text-black dark:!text-white"
              }`}
            >
              {isFullscreen ? (
                <FullscreenExitOutlined />
              ) : (
                <FullscreenOutlined />
              )}
            </Button>
          </Tooltip>
        </div>
      </div>

      {/* Iframe Container */}
      <div
        className={`${
          isFullscreen
            ? "fixed top-0 left-0 w-screen h-screen bg-black z-50 pt-14"
            : "flex justify-center mt-2"
        }`}
      >
        <iframe
          src={currentDashboard.url}
          className="border rounded-lg shadow-lg"
          style={{
            width: isFullscreen ? "100vw" : "1200px",
            height: isFullscreen ? "100vh" : "500px",
          }}
        />
      </div>

      <AddDashboardModal
        visible={showAddDashboardModal}
        onClose={() => !savingDashboard && setShowAddDashboardModal(false)}
        loading={savingDashboard}
        onSave={handleSaveDashboard}
      />
    </div>
  );
};

export default Site24x7_dashboard;
