import React, { useEffect, useState } from "react";
import ISOSummary from "./ISOSummary";
import { notifyError } from "../Notification";

const ISODashboard = ({
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
      <ISOSummary
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

export default ISODashboard;
