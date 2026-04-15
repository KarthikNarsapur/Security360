import React, { useState, useEffect } from "react";
import axios from "axios";
import { motion, AnimatePresence } from "framer-motion";
import { OrbitProgress } from "react-loading-indicators";

export default function OUComponent() {
  const [ous, setOUs] = useState([]);
  const [expanded, setExpanded] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    axios
      .get("http://localhost:8000/getous")
      .then((res) => {
        setOUs(res.data.organizational_units || []);
        setLoading(false);
      })
      .catch((err) => console.error("Error fetching OUs:", err));
    setLoading(false);
  }, []);

  const toggleExpand = (id) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  return (
    <div>
      {/* <h2 className="text-3xl font-bold text-gray-700 mb-6"> Organizational Units</h2> */}
      <h1 className="text-3xl font-bold text-blue-900 dark:text-white mb-6 mt-2">
        Organizational Units
      </h1>

      {loading && (
        <OrbitProgress color="#312e81" size="medium" text="" textColor="" />
      )}
      {ous.map((ou) => (
        <div
          key={ou.Id}
          className="bg-white rounded-xl shadow-md mb-4 p-4 border hover:shadow-xl transition duration-300"
        >
          <div
            className="flex justify-between items-center cursor-pointer"
            onClick={() => toggleExpand(ou.Id)}
          >
            <div>
              <h3 className="text-xl font-semibold text-blue-600">{ou.Name}</h3>
              <p className="text-sm text-gray-500">ID: {ou.Id}</p>
            </div>
            <span className="text-gray-600 text-xl">
              {expanded[ou.Id] ? "▴" : "▾"}
            </span>
          </div>

          <AnimatePresence>
            {expanded[ou.Id] && (
              <motion.div
                className="mt-4"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
              >
                <h4 className="text-lg font-semibold text-gray-700">
                  Accounts:
                </h4>
                {ou.Accounts.length === 0 ? (
                  <p className="text-gray-500 italic">No accounts found</p>
                ) : (
                  <ul className="list-disc ml-6 mt-2 space-y-1">
                    {ou.Accounts.map((acc) => (
                      <li key={acc.Id}>
                        <p>
                          <strong>{acc.Name}</strong> — {acc.Email} (
                          {acc.Status})
                        </p>
                      </li>
                    ))}
                  </ul>
                )}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      ))}
    </div>
  );
}
