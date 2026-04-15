import React, { useEffect, useState } from "react";
import AWAFSummary from "./AWAFSummary";
import { notifyError } from "../Notification";

const AWAFDashboard = ({
  accountDetails,
  modal,
  darkMode,
  setUserName,
  setFullName,
  setAccountDetails,
  setEksAccountDetails,
}) => {
  return (
    <div>
      <AWAFSummary
        accountDetails={accountDetails}
        modal={modal}
        darkMode={darkMode}
        setUserName={setUserName}
        setFullName={setFullName}
        setAccountDetails={setAccountDetails}
        setEksAccountDetails={setEksAccountDetails}
      />
    </div>
  );
};

export default AWAFDashboard;
