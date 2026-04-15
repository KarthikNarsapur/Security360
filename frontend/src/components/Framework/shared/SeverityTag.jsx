// components/Framework/shared/SeverityTag.jsx
import { Tag } from "antd";
import { getSeverityColor } from "../../../utils/frameworkUtils";

/**
 * Renders an Ant Design Tag with the correct severity colour class.
 * Matches the same pattern used in CisSummary's severity column.
 */
const SeverityTag = ({ severity }) => (
  <Tag className={getSeverityColor(severity)}>{severity || "Unknown"}</Tag>
);

export default SeverityTag;
