// components/Framework/shared/DropdownFilter.jsx
import { Dropdown, Button, Checkbox } from "antd";
import { FilterOutlined } from "@ant-design/icons";

/**
 * Reusable dropdown filter - same as CIS but extracted as standalone component.
 *
 * Props:
 *   label    — button label text
 *   options  — array of string options
 *   selected — array of selected values (controlled)
 *   onChange — fn(newSelected: string[])
 */
const DropdownFilter = ({ label, options = [], selected = [], onChange }) => {
  const handleChange = (value, checked) => {
    const next = checked
      ? [...selected, value]
      : selected.filter((v) => v !== value);
    onChange(next);
  };

  return (
    <Dropdown
      trigger={["click"]}
      dropdownRender={() => (
        <div
          style={{
            padding: 12,
            background: "#fff",
            borderRadius: 8,
            boxShadow: "0 2px 8px rgba(0,0,0,0.15)",
            display: "flex",
            flexDirection: "column",
            maxHeight: 200,
            overflowY: "auto",
            minWidth: 160,
          }}
        >
          {options.length === 0 ? (
            <span className="text-gray-400 text-sm">No options</span>
          ) : (
            options.map((opt) => (
              <Checkbox
                key={opt}
                checked={selected.includes(opt)}
                onChange={(e) => handleChange(opt, e.target.checked)}
                style={{ marginBottom: 8 }}
              >
                {opt}
              </Checkbox>
            ))
          )}
        </div>
      )}
    >
      <Button icon={<FilterOutlined />} className="mr-2">
        {label}
        {selected.length > 0 && (
          <span className="ml-1 bg-indigo-600 text-white text-xs rounded-full px-1.5 py-0.5">
            {selected.length}
          </span>
        )}
      </Button>
    </Dropdown>
  );
};

export default DropdownFilter;
