import React, { useState } from "react";
import { Select, Space, Tooltip } from "antd";
import { groupedRegionOptions } from "../../AWSFilters";

const RegionDropdown = ({
  onRegionChange,
  selectedRegions,
  disabled = false,
}) => {
  //   const [selectedRegions, setSelectedRegions] = useState([]);

  const handleChange = (value) => {
    // setSelectedRegions(value);
    onRegionChange(value);
    // console.log(`selected ${value}`);
  };

  return (
    <div>
      <Space style={{ width: "100%" }} direction="vertical">
        <Select
          mode="multiple"
          disabled={disabled}
          showSearch
          allowClear
          placeholder="Select AWS regions to scan"
          onChange={handleChange}
          options={groupedRegionOptions}
          // optionFilterProp="label"
          filterOption={(input, option) => {
            const search = input.toLowerCase();
            const label = option?.label?.toLowerCase() || "";
            const value = option?.value?.toLowerCase() || "";
            return label.includes(search) || value.includes(search);
          }}
          value={selectedRegions}
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

export default RegionDropdown;
