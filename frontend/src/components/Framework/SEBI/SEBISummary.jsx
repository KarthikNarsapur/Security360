// components/Framework/SEBI/SEBISummary.jsx
import FrameworkDashboard from "../shared/FrameworkDashboard";

/**
 * SEBI CSCRF Dashboard.
 * All logic lives in FrameworkDashboard — this just sets frameworkKey="sebi".
 */
const SEBISummary = (props) => (
  <FrameworkDashboard {...props} frameworkKey="sebi" />
);

export default SEBISummary;
