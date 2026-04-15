import React, { useEffect, useState } from "react";
import CisSummary from "./CisSummary";
import { notifyError } from "../Notification";

const CisDashboard = ({
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
      <CisSummary
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

export default CisDashboard;
