import React from "react";
import { Select, Space } from "antd";

const TimerDropdown = ({ rotationSeconds, onChange, disabled = false }) => {
  const timerOptions = [
    { label: "10 Sec", value: 10 },
    { label: "20 Sec", value: 20 },
    { label: "30 Sec", value: 30 },
    { label: "1 Min", value: 60 },
    { label: "2 Min", value: 120 },
    { label: "5 Min", value: 300 },
  ];

  return (
    <Space style={{ width: "100%" }} direction="vertical">
      <Select
        style={{ width: "100%" }}
        value={rotationSeconds}
        onChange={onChange}
        options={timerOptions}
        placeholder="Auto-switch time"
        disabled={disabled}
        popupMatchSelectWidth={false}
      />
    </Space>
  );
};

export default TimerDropdown;
