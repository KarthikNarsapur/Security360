import React from "react";

export default function SidePopup({ finding, onClose }) {
  return (
    <div className="fixed inset-0 flex justify-end z-50 bg-black bg-opacity-30">
      <div className="bg-white w-full max-w-md shadow-lg h-full overflow-y-auto p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-xl font-bold capitalize">
            {finding.title.replace(/_/g, " ")} Details
          </h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-red-600 text-2xl"
          >
            &times;
          </button>
        </div>

        <div className="text-sm text-gray-700">
          <p>
            <strong>Severity:</strong> {finding.severity}
          </p>
          <p>
            <strong>Risk Score:</strong> {finding.risk_score}
          </p>
          <p>
            <strong>Region:</strong> {finding.region}
          </p>
          <p>
            <strong>Account ID:</strong> {finding.account_id}
          </p>
          <p>
            <strong>Resources Affected:</strong> {finding.affected}
          </p>
          <p>
            <strong>Updated At:</strong> {finding.updated_at}
          </p>

          <h3 className="mt-4 mb-2 font-semibold">Resources:</h3>
          {finding.resources?.map((res, i) => (
            <pre
              key={i}
              className="bg-gray-100 p-2 rounded mb-3 overflow-x-auto text-xs"
            >
              {JSON.stringify(res, null, 2)}
            </pre>
          ))}
        </div>
      </div>
    </div>
  );
}
