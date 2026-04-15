import React from "react";
import { Select, Space, Tooltip } from "antd";

const AccountDropdown = ({
  onAccountChange,
  selectedAccounts,
  accountOptions,
  mode = "multiple",
  placeholder = "Select AWS accounts to scan",
  disabled = false,
}) => {
  const handleChange = (value) => {
    onAccountChange(value);
    // console.log(`selected accounts: ${value}`);
  };

  const accountOptionsWithLabel = accountOptions.map((account) => ({
    label: `${account.account_id} ${
      account.account_name ? `(${account.account_name})` : ""
    }`,
    value: JSON.stringify(account),
  }));

  return (
    <div>
      <Space style={{ width: "100%" }} direction="vertical">
        <Select
          mode={mode === "multiple" ? "multiple" : undefined}
          disabled={disabled}
          showSearch
          allowClear
          placeholder={placeholder}
          onChange={handleChange}
          options={accountOptionsWithLabel}
          value={selectedAccounts}
          style={{ width: "100%" }}
          popupMatchSelectWidth={false}
          styles={{
            popup: {
              root: { minWidth: "200px" },
            },
          }}
          maxTagCount="responsive"
          maxTagPlaceholder={(omittedValues) => (
            <Tooltip
              styles={{ root: { pointerEvents: "none" } }}
              title={omittedValues.map(({ label }) => label).join(", ")}
            >
              <span>+{omittedValues.length} more</span>
            </Tooltip>
          )}
          filterOption={(input, option) =>
            (option?.label ?? "").toLowerCase().includes(input.toLowerCase()) ||
            (option?.value ?? "").toLowerCase().includes(input.toLowerCase())
          }
        />
      </Space>
    </div>
  );
};

export default AccountDropdown;
