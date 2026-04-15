// components/Framework/RBI/RBISummary.jsx
import FrameworkDashboard from "../shared/FrameworkDashboard";

/**
 * RBI CSF Dashboard.
 * All logic lives in FrameworkDashboard — this just sets frameworkKey="rbi".
 */
const RBISummary = (props) => (
  <FrameworkDashboard {...props} frameworkKey="rbi" />
);

export default RBISummary;
