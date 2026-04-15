import React from "react";
import { Select, Space, Tooltip } from "antd";

const scanTypeOptions = [
  { label: "CloudTrail Findings", value: "cloudtrail" },
  { label: "VPC Flow Logs Findings", value: "vpc" },
];

const ScanTypeDropdown = ({
  onScanTypeChange,
  selectedScanTypes,
  mode = "multiple",
  placeholder = "Select scan types",
  disabled = false,
}) => {
  const handleChange = (value) => {
    onScanTypeChange(value);
  };

  return (
    <div>
      <Space style={{ width: "100%" }} direction="vertical">
        <Select
          mode={mode === "multiple" ? "multiple" : undefined}
          disabled={disabled}
          showSearch={false}
          allowClear
          placeholder={placeholder}
          onChange={handleChange}
          options={scanTypeOptions}
          value={selectedScanTypes}
          style={{ width: "100%" }}
          maxTagCount="responsive"
          popupMatchSelectWidth={false}
          styles={{
            popup: {
              root: { minWidth: "200px" },
            },
          }}
          maxTagPlaceholder={(omittedValues) => (
            <Tooltip
              styles={{ root: { pointerEvents: "none" } }}
              title={omittedValues.map(({ label }) => label).join(", ")}
            >
              <span>+{omittedValues.length} more</span>
            </Tooltip>
          )}
        />
      </Space>
    </div>
  );
};

export default ScanTypeDropdown;
