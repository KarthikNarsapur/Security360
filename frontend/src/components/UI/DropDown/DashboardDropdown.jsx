// src/components/DashboardDropdown.js
import React from "react";
import { Select, Space, Tooltip } from "antd";

const DashboardDropdown = ({
  dashboards = [],
  selectedDashboard,
  onDashboardChange,
  disabled = false,
  placeholder = "Select customer dashboard",
}) => {
  const dashboardOptions = dashboards.map((item) => ({
    label: item.clientName,
    value: JSON.stringify(item),
  }));

  const handleChange = (value) => {
    const parsed = JSON.parse(value);
    onDashboardChange(parsed);
  };

  return (
    <div>
      <Space style={{ width: "100%" }} direction="vertical">
        <Select
          showSearch
          allowClear
          disabled={disabled}
          placeholder={placeholder}
          style={{ width: "100%" }}
          onChange={handleChange}
          value={
            selectedDashboard ? JSON.stringify(selectedDashboard) : undefined
          }
          options={dashboardOptions}
          filterOption={(input, option) =>
            (option?.label ?? "").toLowerCase().includes(input.toLowerCase())
          }
          styles={{
            popup: {
              root: { minWidth: "200px" },
            },
          }}
          popupMatchSelectWidth={false}
        />
      </Space>
    </div>
  );
};

export default DashboardDropdown;
