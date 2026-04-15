import React, { useState } from "react";
import { Modal, Input } from "antd";

const AddDashboardModal = ({ visible, onClose, onSave, loading = false }) => {
  const [form, setForm] = useState({
    clientName: "",
    url: "",
  });

  const handleChange = (key, value) => {
    setForm({ ...form, [key]: value });
  };

  const resetForm = () => {
    setForm({ clientName: "", url: "" });
  };

  return (
    <Modal
      title={
        <span className="text-xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
          Add Dashboard
        </span>
      }
      open={visible}
      onCancel={loading ? null : onClose}
      onOk={() => !loading && onSave(form, resetForm)}
      okText="Add Dashboard"
      cancelText="Cancel"
      okButtonProps={{
        loading,
        disabled: loading,
        className:
          "!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 !text-white !border-0 rounded-xl px-6 py-2 shadow-lg hover:shadow-xl transition-all duration-200",
      }}
      cancelButtonProps={{
        disabled: loading,
        className:
          "!bg-white/80 dark:!bg-slate-800/80 !text-slate-700 dark:!text-slate-300 !border !border-slate-300 dark:!border-slate-600 rounded-xl px-6 py-2 shadow-md hover:shadow-lg transition-all",
      }}
      className="rounded-2xl backdrop-blur-md"
      maskClosable={false}
      destroyOnHidden
      forceRender
      modalRender={(node) => node} // prevents width recalculation
      rootClassName="no-body-padding"
    >
      <div className="mt-2 space-y-4">
        <div>
          <p className="font-semibold mb-1 text-slate-700 dark:text-slate-300">
            Client Name
          </p>
          <Input
            placeholder="Enter client name"
            disabled={loading}
            value={form.clientName}
            onChange={(e) => handleChange("clientName", e.target.value)}
            className="h-11 rounded-xl border-slate-300 dark:border-slate-600 bg-white/70 dark:bg-slate-800/50 backdrop-blur-sm"
          />
        </div>

        <div>
          <p className="font-semibold mb-1 text-slate-700 dark:text-slate-300">
            Dashboard URL
          </p>
          <Input
            placeholder="Enter dashboard URL"
            disabled={loading}
            value={form.url}
            onChange={(e) => handleChange("url", e.target.value)}
            className="h-11 rounded-xl border-slate-300 dark:border-slate-600 bg-white/70 dark:bg-slate-800/50 backdrop-blur-sm"
          />
        </div>
      </div>
    </Modal>
  );
};

export default AddDashboardModal;
