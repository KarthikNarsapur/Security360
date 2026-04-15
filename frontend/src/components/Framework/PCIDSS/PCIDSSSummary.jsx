// components/Framework/PCIDSS/PCIDSSSummary.jsx
import FrameworkDashboard from "../shared/FrameworkDashboard";

/**
 * PCI-DSS v4.0 Dashboard.
 * All logic lives in FrameworkDashboard — this just sets frameworkKey="pcidss".
 */
const PCIDSSSummary = (props) => (
  <FrameworkDashboard {...props} frameworkKey="pcidss" />
);

export default PCIDSSSummary;
