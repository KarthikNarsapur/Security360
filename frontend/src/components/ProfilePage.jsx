import { useEffect, useState } from "react";
import { IoLocationSharp, IoArrowBack } from "react-icons/io5";
import { MdEmail, MdModeEdit } from "react-icons/md";
import { FaCheck, FaTimes, FaCamera, FaSave, FaTrash } from "react-icons/fa";
import { useNavigate, UNSAFE_NavigationContext } from "react-router-dom";
import { MdBusiness } from "react-icons/md";
import { FaRegUser } from "react-icons/fa";
import ImagePopup from "./ImagePopup";
import { PiKeyBold } from "react-icons/pi";
import { IoLogOutOutline } from "react-icons/io5";
import Cookies from "js-cookie";
import { notifyError, notifyInfo, notifySuccess } from "./Notification";
import { LoadingSkeletonProfilePage } from "./LoadingSkeleton";
import AccountsPage from "./AccountsPage";

function ProfilePage() {
  const [profileDetails, setProfileDetails] = useState({
    full_name: "",
    username: "",
    email: "",
    address: "",
    company: "",
    roles_info: [],
    kubernetes_roles_info: [],
    profileImage: null,
    profileImagePreview: null,
  });
  const [originalDetails, setOriginalDetails] = useState({});
  const [isEditing, setIsEditing] = useState({
    full_name: false,
    address: false,
    company: false,
  });
  const [tempDetails, setTempDetails] = useState({ ...profileDetails });
  const [showImagePopup, setShowImagePopup] = useState(false);
  const [loading, setLoading] = useState(true);
  const [hasChanges, setHasChanges] = useState(false);
  const [activeTab, setActiveTab] = useState("profile"); // state for tab switching
  const [profileUpdateLoading, setProfileUpdateLoading] = useState(false);

  const [username, setUsername] = useState(localStorage.getItem("username"));

  const navigate = useNavigate();

  const handleBackToDashboard = () => {
    if (hasChanges) {
      const confirmLeave = window.confirm(
        "You have unsaved changes. Are you sure you want to leave?"
      );
      if (!confirmLeave) return;
    }
    navigate("/dashboard");
  };

  // Warn user if they try to leave the page (closing tab, refresh, typing new URL)
  useEffect(() => {
    const handleBeforeUnload = (e) => {
      if (hasChanges) {
        e.preventDefault();
        e.returnValue = ""; // Standard for most browsers
      }
    };

    window.addEventListener("beforeunload", handleBeforeUnload);

    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
    };
  }, [hasChanges]);

  const handleEdit = (field) => {
    setTempDetails({ ...profileDetails });
    setIsEditing((prev) => ({ ...prev, [field]: true }));
  };

  const handleSave = (field) => {
    setProfileDetails((prev) => ({ ...prev, [field]: tempDetails[field] }));
    setIsEditing((prev) => ({ ...prev, [field]: false }));
    checkForChanges({ ...profileDetails, [field]: tempDetails[field] });
  };

  const handleCancel = (field) => {
    setTempDetails({ ...profileDetails });
    setIsEditing((prev) => ({ ...prev, [field]: false }));
  };

  const handleImageChange = (file) => {
    if (file) {
      const validTypes = ["image/jpeg", "image/png"];
      const maxSize = 5 * 1024 * 1024; // 5MB

      if (!validTypes.includes(file.type)) {
        notifyError("Only JPEG and PNG images are allowed.");
        return;
      }
      if (file.size > maxSize) {
        notifyError("File size must be less than 5 MB.");
        return;
      }

      const previewUrl = URL.createObjectURL(file);
      setProfileDetails((prev) => {
        const updated = {
          ...prev,
          profileImage: file,
          profileImagePreview: previewUrl,
        };
        checkForChanges(updated);
        return updated;
      });
    }
  };

  const handleImageClose = () => {
    setShowImagePopup(false);
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
      console.log(error);
    }
  };

  const InitialsAvatar = ({ full_name, size = "w-32 h-32" }) => {
    const getInitials = (full_name) => {
      if (!full_name) return "U";
      return full_name.charAt(0).toUpperCase();
    };

    const getAvatarColor = (full_name) => {
      if (!full_name) return "from-indigo-500 to-indigo-600";

      const colors = [
        "from-indigo-500 to-indigo-600",
        "from-purple-500 to-purple-600",
        "from-blue-500 to-blue-600",
        "from-green-500 to-green-600",
        "from-yellow-500 to-yellow-600",
        "from-red-500 to-red-600",
        "from-pink-500 to-pink-600",
        "from-teal-500 to-teal-600",
      ];

      const charCode = full_name.charCodeAt(0);
      return colors[charCode % colors.length];
    };

    return (
      <div
        className={`${size} rounded-2xl bg-gradient-to-br ${getAvatarColor(
          full_name
        )} flex items-center justify-center text-white font-bold text-[70px] shadow-xl border-4 border-white dark:border-slate-800`}
      >
        {getInitials(full_name)}
      </div>
    );
  };

  const fetchProfileDetails = async () => {
    try {
      setLoading(true);
      const backend_url = process.env.REACT_APP_BACKEND_URL;
      const payload = {
        access_token: Cookies.get("access_token"),
      };
      if (!payload.access_token) {
        notifyInfo("Session expired, login again..");
        navigate("/login");
        return;
      }
      const response = await fetch(`${backend_url}/api/getprofile`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      if (result?.status === "ok") {
        const profileData = result.response?.profileDetails || {};
        setProfileDetails(profileData);
        setOriginalDetails(profileData);
        setUsername(profileData?.username || localStorage.getItem("username") || "");
        // console.log("result: ", result);
      } else {
        console.log("failed to fetch profile details");
      }
    } catch (err) {
      console.log("error: ", err);
    } finally {
      setLoading(false);
    }
  };

  const checkForChanges = (currentDetails = profileDetails) => {
    // console.log("current details: ", currentDetails);
    // console.log("original details: ", originalDetails);
    const changed = Object.keys(originalDetails).some(
      (key) => originalDetails[key] !== currentDetails[key]
    );
    // console.log("changed: ", changed);
    setHasChanges(changed);
  };

  const handleSaveAllChanges = async () => {
    setProfileUpdateLoading(true);
    try {
      const accessToken = Cookies.get("access_token");

      if (!accessToken) {
        notifyError("Session expired. Please login again.");
        navigate("/login");
        return;
      }
      const formData = new FormData();

      // Build changed fields
      const changedFields = { username: username };

      Object.keys(profileDetails).forEach((key) => {
        if (
          profileDetails[key] !== originalDetails[key] &&
          key !== "profileImage" &&
          key !== "profileImagePreview"
        ) {
          changedFields[key] = profileDetails[key];
        }
      });

      formData.append("update_data", JSON.stringify(changedFields));

      if (
        profileDetails.profileImage &&
        profileDetails.profileImage instanceof File
      ) {
        formData.append("profile_image", profileDetails.profileImage);
      }

      // console.log("formData entries:");
      // for (let [key, value] of formData.entries()) {
      //   console.log(key, value);
      // }

      const backend_url = process.env.REACT_APP_BACKEND_URL;

      const response = await fetch(`${backend_url}/api/updateprofile`, {
        method: "POST",
        // headers: {
        //   "Content-Type": "application/json",
        // },
        body: formData,
      });

      const result = await response.json();

      if (result.status === "ok") {
        notifySuccess("Profile updated successfully!");
        setOriginalDetails({ ...profileDetails });
        setHasChanges(false);
        if (changedFields.full_name) {
          localStorage.setItem("full_name", changedFields.full_name);
        }
      } else {
        notifyError(result.error_message || "Failed to update profile");
      }
    } catch (error) {
      console.error("Update profile error:", error);
      notifyError("An error occurred while updating profile");
    } finally {
      setProfileUpdateLoading(false);
    }
  };

  useEffect(() => {
    fetchProfileDetails();
  }, []);

  useEffect(() => {
    if (Object.keys(originalDetails).length > 0) {
      checkForChanges();
    }
  }, [profileDetails]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 p-8 flex flex-col items-center">
      {loading ? (
        <LoadingSkeletonProfilePage />
      ) : (
        <>
          <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-2xl shadow-indigo-500/10 w-full max-w-4xl relative overflow-hidden">
            {/* Header with gradient and back button */}
            <div className="h-32 bg-gradient-to-r from-indigo-600 via-indigo-700 to-indigo-800 dark:from-slate-800 dark:via-slate-700 dark:to-slate-600 relative">
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent"></div>
              {/* Back to Dashboard Button */}
              <button
                onClick={handleBackToDashboard}
                className="absolute top-4 left-4 p-2 bg-white/20 hover:bg-white/30 backdrop-blur-sm rounded-lg transition-all duration-200 text-white hover:text-indigo-100"
              >
                <IoArrowBack className="w-6 h-6" />
              </button>
            </div>

            {/* Profile Image */}
            <div className="absolute left-8 top-16 group">
              <div className="relative">
                {profileDetails?.profileImagePreview ||
                  profileDetails?.profileImage ? (
                  <img
                    src={
                      profileDetails.profileImagePreview ||
                      profileDetails.profileImage
                    }
                    className="w-32 h-32 rounded-2xl object-cover border-4 border-white dark:border-slate-800 shadow-xl transition-all duration-300 group-hover:brightness-75"
                    alt="Profile"
                  />
                ) : (
                  <InitialsAvatar full_name={profileDetails?.full_name} />
                )}
                <button
                  onClick={() => setShowImagePopup(true)}
                  className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity bg-black/20 rounded-2xl"
                >
                  <FaCamera className="text-white text-2xl" />
                </button>
              </div>
            </div>

            {/* Profile Name */}
            <div className="pt-2 pb-8 px-8">
              <div className="ml-40">
                {!isEditing.full_name ? (
                  <div className="flex items-center gap-3">
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white">
                      {profileDetails?.full_name}
                    </h1>
                    <button
                      onClick={() => handleEdit("full_name")}
                      className="p-2 text-indigo-600 hover:text-indigo-700 dark:text-indigo-400 dark:hover:text-indigo-300 hover:bg-indigo-50 dark:hover:bg-slate-800 rounded-lg transition-all duration-200"
                    >
                      <MdModeEdit className="w-5 h-5" />
                    </button>
                  </div>
                ) : (
                  <div className="flex items-center gap-3">
                    <input
                      type="text"
                      value={tempDetails.full_name}
                      onChange={(e) =>
                        setTempDetails({
                          ...tempDetails,
                          full_name: e.target.value,
                        })
                      }
                      className="text-2xl font-bold bg-white dark:bg-slate-800 border border-indigo-200 dark:border-slate-600 rounded-lg px-3 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                    />
                    <button
                      onClick={() => handleSave("full_name")}
                      className="p-2 text-green-600 hover:text-green-700 hover:bg-green-50 dark:hover:bg-green-900/20 rounded-lg transition-all duration-200"
                    >
                      <FaCheck className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleCancel("full_name")}
                      className="p-2 text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-all duration-200"
                    >
                      <FaTimes className="w-4 h-4" />
                    </button>
                  </div>
                )}

                {/* Tab Toggle Buttons */}
                {/* <div className="flex gap-2 mt-4">
                  <button
                    onClick={() => setActiveTab("profile")}
                    className={`px-4 py-2 rounded-lg font-medium transition-all duration-200 border-2 ${
                      activeTab === "profile"
                        ? "bg-indigo-600 text-white shadow-lg border-indigo-600"
                        : "bg-indigo-50 dark:bg-slate-800 text-indigo-600 dark:text-indigo-400 border-indigo-300 dark:border-slate-600 hover:bg-indigo-100 dark:hover:bg-slate-700"
                    }`}
                  >
                    Profile Information
                  </button>
                  <button
                    onClick={() => setActiveTab("accounts")}
                    className={`px-4 py-2 rounded-lg font-medium transition-all duration-200 border-2 ${
                      activeTab === "accounts"
                        ? "bg-indigo-600 text-white shadow-lg border-indigo-600"
                        : "bg-indigo-50 dark:bg-slate-800 text-indigo-600 dark:text-indigo-400 border-indigo-300 dark:border-slate-600 hover:bg-indigo-100 dark:hover:bg-slate-700"
                    }`}
                  >
                    Accounts
                  </button>
                </div> */}
              </div>
            </div>
          </div>

          {/* Profile Details */}
          <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-2xl shadow-indigo-500/10 w-full max-w-4xl mt-6 p-8">
            <div className="space-y-6">
              {/* Username */}
              <div className="flex items-center gap-4 p-4 bg-gradient-to-r from-indigo-50 to-indigo-100 dark:from-slate-800 dark:to-slate-700 rounded-xl">
                <FaRegUser className="text-indigo-600 dark:text-indigo-400 text-xl" />
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Username
                  </label>
                  <p className="text-lg font-semibold text-slate-900 dark:text-white">
                    {profileDetails?.username}
                  </p>
                </div>
              </div>

              {/* Email */}
              <div className="flex items-center gap-4 p-4 bg-gradient-to-r from-indigo-50 to-indigo-100 dark:from-slate-800 dark:to-slate-700 rounded-xl">
                <MdEmail className="text-indigo-600 dark:text-indigo-400 text-xl" />
                <div>
                  <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                    Email
                  </label>
                  <p className="text-lg font-semibold text-slate-900 dark:text-white">
                    {profileDetails?.email}
                  </p>
                </div>
              </div>

              <div className="h-px bg-slate-200 dark:bg-slate-700"></div>

              {/* Company */}
              <div className="flex items-center gap-4 p-4 bg-gradient-to-r from-slate-50 to-slate-100 dark:from-slate-800 dark:to-slate-700 rounded-xl">
                <MdBusiness className="text-indigo-600 dark:text-indigo-400 text-xl" />
                <div className="flex-1">
                  {!isEditing.company ? (
                    <div className="flex items-center justify-between">
                      <div>
                        <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                          Organization
                        </label>
                        <p className="text-lg font-semibold text-slate-900 dark:text-white">
                          {profileDetails?.company}
                        </p>
                      </div>
                      <button
                        onClick={() => handleEdit("company")}
                        className="p-2 text-indigo-600 hover:text-indigo-700 dark:text-indigo-400 dark:hover:text-indigo-300 hover:bg-indigo-50 dark:hover:bg-slate-800 rounded-lg transition-all duration-200"
                      >
                        <MdModeEdit className="w-5 h-5" />
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-3">
                      <div className="flex-1">
                        <label className="text-sm font-medium text-slate-600 dark:text-slate-400">
                          Organization
                        </label>
                        <input
                          type="text"
                          value={tempDetails.company}
                          onChange={(e) =>
                            setTempDetails({
                              ...tempDetails,
                              company: e.target.value,
                            })
                          }
                          className="w-full bg-white dark:bg-slate-800 border border-indigo-200 dark:border-slate-600 rounded-lg px-3 py-2 text-slate-900 dark:text-white focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
                        />
                      </div>
                      <button
                        onClick={() => handleSave("company")}
                        className="p-2 text-green-600 hover:text-green-700 hover:bg-green-50 dark:hover:bg-green-900/20 rounded-lg transition-all duration-200"
                      >
                        <FaCheck className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => handleCancel("company")}
                        className="p-2 text-red-600 hover:text-red-700 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-all duration-200"
                      >
                        <FaTimes className="w-4 h-4" />
                      </button>
                    </div>
                  )}
                </div>
              </div>

              {/* save and discard changes buttons */}
              {hasChanges && (
                <div className="mt-8 flex justify-center gap-4">
                  <button
                    onClick={handleSaveAllChanges}
                    disabled={profileUpdateLoading}
                    className="flex items-center gap-3 bg-gradient-to-r from-emerald-600 to-emerald-700 hover:from-emerald-700 hover:to-emerald-800 text-white px-8 py-3 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-60"
                  >
                    {profileUpdateLoading ? (
                      <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                    ) : (
                      <>
                        <FaSave className="w-4 h-4" />
                        <span className="font-semibold">Save All Changes</span>
                      </>
                    )}
                  </button>

                  <button
                    onClick={() => {
                      setProfileDetails({ ...originalDetails });
                      setTempDetails({ ...originalDetails });
                      setHasChanges(false);
                    }}
                    className="flex items-center gap-3 bg-red-600 hover:bg-red-700 text-white px-8 py-3 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                  >
                    <FaTimes className="w-4 h-4" />
                    <span className="font-semibold">Discard All Changes</span>
                  </button>
                </div>
              )}

              <div className="h-px bg-slate-200 dark:bg-slate-700"></div>

              {/* Actions */}
              <div className="space-y-4">
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-4 w-full p-4 bg-gradient-to-r from-red-50 to-red-100 dark:from-red-900/20 dark:to-red-800/20 hover:from-red-100 hover:to-red-200 dark:hover:from-red-800/30 dark:hover:to-red-700/30 rounded-xl transition-all duration-200"
                >
                  <IoLogOutOutline className="text-red-600 dark:text-red-400 text-xl" />
                  <span className="text-lg font-semibold text-red-700 dark:text-red-300">
                    Logout
                  </span>
                </button>
              </div>
            </div>
          </div>
        </>
      )}
      {showImagePopup && (
        <ImagePopup
          imageSrc={profileDetails?.profileImagePreview || ""}
          onClose={handleImageClose}
          onImageChange={handleImageChange}
        />
      )}
    </div>
  );
}

export default ProfilePage;
