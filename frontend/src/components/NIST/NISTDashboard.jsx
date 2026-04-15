import React, { useEffect, useState } from "react";
import NISTSummary from "./NISTSummary";
import { notifyError } from "../Notification";

const NISTDashboard = ({
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
      <NISTSummary
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

export default NISTDashboard;
