// ../UI/DropDown/PillarDropdown.jsx
import React from "react";
import { Select, Tooltip } from "antd";

const PILLAR_OPTIONS = [
  "Operational Excellence",
  "Security",
  "Reliability",
  "Performance Efficiency",
  "Cost Optimization",
  "Sustainability",
];

const PillarDropdown = ({
  selectedPillar,
  onPillarChange,
  disabled = false,
}) => {
  return (
    <Select
      showSearch
      mode="multiple"
      allowClear
      maxTagCount="responsive"
      value={selectedPillar}
      onChange={onPillarChange}
      placeholder="Select pillar"
      disabled={disabled}
      className="w-full"
      popupMatchSelectWidth={false}
      styles={{
        popup: {
          root: { minWidth: "200px" },
        },
      }}
      options={PILLAR_OPTIONS.map((pillar) => ({
        label: pillar,
        value: pillar,
      }))}
      maxTagPlaceholder={(omittedValues) => (
        <Tooltip
          styles={{ root: { pointerEvents: "none" } }}
          title={omittedValues.map(({ label }) => label).join(", ")}
        >
          <span>+{omittedValues.length} more</span>
        </Tooltip>
      )}
    />
  );
};

export default PillarDropdown;
