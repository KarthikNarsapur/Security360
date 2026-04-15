// components/Framework/shared/JsonRenderer.jsx
import { useState } from "react";
import { ChevronRight, ChevronDown } from "lucide-react";

const JsonRenderer = ({ data, level = 0 }) => {
  const [expandedKeys, setExpandedKeys] = useState(new Set());

  const toggleExpanded = (key) => {
    const next = new Set(expandedKeys);
    next.has(key) ? next.delete(key) : next.add(key);
    setExpandedKeys(next);
  };

  const renderValue = (key, value, currentLevel) => {
    const uniqueKey = `${currentLevel}-${key}`;

    if (value === null || value === undefined)
      return <span className="text-gray-400 italic">null</span>;

    if (typeof value === "boolean")
      return (
        <span
          className={`font-medium ${value ? "text-green-600" : "text-red-600"}`}
        >
          {value.toString()}
        </span>
      );

    if (typeof value === "number")
      return <span className="text-blue-600 font-medium">{value}</span>;

    if (typeof value === "string") {
      if (value.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/))
        return (
          <span className="text-purple-600">
            {new Date(value).toLocaleString()}
          </span>
        );
      if (value.startsWith("arn:aws:"))
        return (
          <span className="text-indigo-600 font-mono text-sm break-all">
            {value}
          </span>
        );
      if (value.match(/^\d+\.\d+\.\d+\.\d+(\/\d+)?$/))
        return <span className="text-orange-600 font-mono">{value}</span>;
      return <span className="text-gray-700">{value}</span>;
    }

    if (Array.isArray(value)) {
      if (value.length === 0)
        return <span className="text-gray-400 italic">[]</span>;
      const isExpanded = expandedKeys.has(uniqueKey);
      return (
        <div>
          <button
            onClick={() => toggleExpanded(uniqueKey)}
            className="flex items-center text-sm text-blue-600 hover:text-blue-800 font-medium"
          >
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 mr-1" />
            ) : (
              <ChevronRight className="w-4 h-4 mr-1" />
            )}
            Array ({value.length} items)
          </button>
          {isExpanded && (
            <div className="ml-4 mt-2 space-y-2">
              {value.map((item, index) => (
                <div key={index} className="border-l-2 border-gray-200 pl-3">
                  <div className="text-sm font-medium text-gray-500 mb-1">
                    [{index}]
                  </div>
                  <JsonRenderer data={item} level={currentLevel + 1} />
                </div>
              ))}
            </div>
          )}
        </div>
      );
    }

    if (typeof value === "object") {
      const keys = Object.keys(value);
      if (keys.length === 0)
        return <span className="text-gray-400 italic">{"{}"}</span>;
      const isExpanded = expandedKeys.has(uniqueKey);
      return (
        <div>
          <button
            onClick={() => toggleExpanded(uniqueKey)}
            className="flex items-center text-sm text-blue-600 hover:text-blue-800 font-medium"
          >
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 mr-1" />
            ) : (
              <ChevronRight className="w-4 h-4 mr-1" />
            )}
            Object ({keys.length} properties)
          </button>
          {isExpanded && (
            <div className="ml-4 mt-2">
              <JsonRenderer data={value} level={currentLevel + 1} />
            </div>
          )}
        </div>
      );
    }

    return <span className="text-gray-700">{String(value)}</span>;
  };

  if (!data || typeof data !== "object")
    return <div className="text-gray-500 italic">No data available</div>;

  return (
    <div className="space-y-3">
      {Object.entries(data).map(([key, value]) => (
        <div
          key={key}
          className={level > 0 ? "border-l-2 border-gray-100 pl-4" : ""}
        >
          <div className="flex items-start gap-3">
            <div className="min-w-0 flex-1">
              <div className="text-sm font-medium text-gray-900 mb-1">
                {key
                  .replace(/_/g, " ")
                  .replace(/\b\w/g, (l) => l.toUpperCase())}
              </div>
              <div className="text-sm">{renderValue(key, value, level)}</div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default JsonRenderer;
