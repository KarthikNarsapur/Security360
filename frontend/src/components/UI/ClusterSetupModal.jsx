import { useState, useEffect, useRef } from "react";
import { Modal, Button, Select, Tooltip } from "antd";
import {
  notifyError,
  notifyRedirectToContact,
  notifySuccess,
} from "../Notification";
import Cookies from "js-cookie";
import { useNavigate } from "react-router-dom";
import AnsiToHtml from "ansi-to-html";
import {
  Settings,
  Search,
  Rocket,
  Trash2,
  Scan,
  Play,
  Info,
} from "lucide-react";
const ansiConverter = new AnsiToHtml();

const setupOptions = [
  { label: "List NameSpaces", key: "listnamespace" },
  { label: "ArgoCD", key: "argocd" },
  { label: "Falco", key: "falco" },
  { label: "Gatekeeper", key: "gatekeeper" },
  { label: "Kured", key: "kured" },
  { label: "Headlamp", key: "headlamp" },
  { label: "Kubescape", key: "kubescape" },
  { label: "Kubehunter", key: "kubehunter" },
];

const toolDescriptions = {
  listnamespace:
    "Enumerates every Kubernetes namespace in your EKS cluster. A fundamental step to map resource boundaries, isolate workloads, and understand cluster organization at a glance.",
  argocd:
    "A GitOps powerhouse for Kubernetes. Continuously syncs your EKS workloads with your Git repos, automating deployments while boosting security, compliance, and reliability.",
  falco:
    "Real-time runtime security for Kubernetes. Monitors syscalls and kernel events in your EKS nodes to instantly detect anomalies, intrusions, and malicious behavior.",
  gatekeeper:
    "OPA-powered policy enforcement for Kubernetes. Validates and enforces fine-grained security, compliance, and resource governance rules across your entire EKS cluster.",
  kured:
    "The Kubernetes reboot orchestrator. Automates safe, rolling node reboots to apply critical OS patches—keeping your EKS worker nodes secure without downtime.",
  headlamp:
    "A sleek, intuitive Kubernetes dashboard. Simplifies EKS cluster management with clear visualizations of resources, workloads, and security insights—all in one place.",
  kubescape:
    "Full-spectrum Kubernetes security scanner. Runs RBAC analysis, vulnerability detection, and compliance audits aligned with NSA and MITRE security frameworks for your EKS workloads.",
  kubehunter:
    "Offensive security for Kubernetes. Actively probes your EKS cluster for vulnerabilities and misconfigurations, simulating attacker behavior to reveal real-world risks.",
};

const groupedToolOptions = [
  {
    label: "Namespace Tools",
    options: [
      {
        label: (
          <div className="flex items-center gap-2 py-1">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="flex items-center gap-2">
              List NameSpaces
              <Tooltip
                title={toolDescriptions.listnamespace}
                placement="right"
                styles={{ root: { maxWidth: "300px" } }}
              >
                <Info className="w-3 h-3 text-slate-400 hover:text-indigo-500 cursor-help" />
              </Tooltip>
            </span>
          </div>
        ),
        value: "listnamespace",
      },
    ],
  },
  {
    label: "Security Scanning Tools",
    options: [
      {
        label: (
          <div className="flex items-center gap-2 py-1">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="flex items-center gap-2">
              Kubescape
              <Tooltip
                title={toolDescriptions.kubescape}
                placement="right"
                styles={{ root: { maxWidth: "300px" } }}
              >
                <Info className="w-3 h-3 text-slate-400 hover:text-indigo-500 cursor-help" />
              </Tooltip>
              <span className="ml-1 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20">
                PRO
              </span>
            </span>
          </div>
        ),
        value: "kubescape",
      },
      {
        label: (
          <div className="flex items-center gap-2 py-1">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="flex items-center gap-2">
              Kubehunter
              <Tooltip
                title={toolDescriptions.kubehunter}
                placement="right"
                styles={{ root: { maxWidth: "300px" } }}
              >
                <Info className="w-3 h-3 text-slate-400 hover:text-indigo-500 cursor-help" />
              </Tooltip>
              <span className="ml-1 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20">
                PRO
              </span>
            </span>
          </div>
        ),
        value: "kubehunter",
      },
    ],
  },
  {
    label: "Management Tools",
    options: [
      {
        label: (
          <div className="flex items-center gap-2 py-1">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="flex items-center gap-2">
              ArgoCD
              <Tooltip
                title={toolDescriptions.argocd}
                placement="right"
                styles={{ root: { maxWidth: "300px" } }}
              >
                <Info className="w-3 h-3 text-slate-400 hover:text-indigo-500 cursor-help" />
              </Tooltip>
              <span className="ml-1 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20">
                PRO
              </span>
            </span>
          </div>
        ),
        value: "argocd",
      },
      {
        label: (
          <div className="flex items-center gap-2 py-1">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="flex items-center gap-2">
              Falco
              <Tooltip
                title={toolDescriptions.falco}
                placement="right"
                styles={{ root: { maxWidth: "300px" } }}
              >
                <Info className="w-3 h-3 text-slate-400 hover:text-indigo-500 cursor-help" />
              </Tooltip>
              <span className="ml-1 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20">
                PRO
              </span>
            </span>
          </div>
        ),
        value: "falco",
      },
      {
        label: (
          <div className="flex items-center gap-2 py-1">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="flex items-center gap-2">
              Gatekeeper
              <Tooltip
                title={toolDescriptions.gatekeeper}
                placement="right"
                styles={{ root: { maxWidth: "300px" } }}
              >
                <Info className="w-3 h-3 text-slate-400 hover:text-indigo-500 cursor-help" />
              </Tooltip>
              <span className="ml-1 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20">
                PRO
              </span>
            </span>
          </div>
        ),
        value: "gatekeeper",
      },
      {
        label: (
          <div className="flex items-center gap-2 py-1">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="flex items-center gap-2">
              Kured
              <Tooltip
                title={toolDescriptions.kured}
                placement="right"
                styles={{ root: { maxWidth: "300px" } }}
              >
                <Info className="w-3 h-3 text-slate-400 hover:text-indigo-500 cursor-help" />
              </Tooltip>
              <span className="ml-1 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20">
                PRO
              </span>
            </span>
          </div>
        ),
        value: "kured",
      },
      {
        label: (
          <div className="flex items-center gap-2 py-1">
            <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
            <span className="flex items-center gap-2">
              Headlamp
              <Tooltip
                title={toolDescriptions.headlamp}
                placement="right"
                styles={{ root: { maxWidth: "300px" } }}
              >
                <Info className="w-3 h-3 text-slate-400 hover:text-indigo-500 cursor-help" />
              </Tooltip>
              <span className="ml-1 px-2 py-0.5 text-xs font-bold text-white bg-gradient-to-r from-indigo-600 to-purple-600 rounded-full shadow-lg shadow-indigo-500/20">
                PRO
              </span>
            </span>
          </div>
        ),
        value: "headlamp",
      },
    ],
  },
];

const allActionTypes = [
  {
    label: "Set Up",
    key: "setup",
    icon: Settings,
    color: "#4f46e5",
  },
  {
    label: "Debug",
    key: "debug",
    icon: Search,
    color: "#ea580c",
  },
  {
    label: "Remove",
    key: "remove",
    icon: Trash2,
    color: "#dc2626",
  },
  {
    label: "Run Scan",
    key: "scan",
    icon: Scan,
    color: "#059669",
  },
];

const toolActionMap = {
  listnamespace: ["setup"],
  argocd: ["setup", "debug", "remove"],
  falco: ["setup", "debug", "remove"],
  gatekeeper: ["setup", "debug", "remove"],
  kured: ["setup", "debug", "remove"],
  headlamp: ["setup", "debug", "remove"],
  kubescape: ["scan"],
  kubehunter: ["scan"],
};

const ClusterSetupModal = ({ visible, onClose, clusterName, clusterData }) => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(false);
  const [socket, setSocket] = useState(null);
  const [selectedTool, setSelectedTool] = useState(null);
  const [selectedAction, setSelectedAction] = useState(null);
  const navigate = useNavigate();
  const logEndRef = useRef(null);

  const backend_url = process.env.REACT_APP_BACKEND_URL;

  const scrollToBottom = () => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);
  useEffect(() => {
    if (selectedTool) {
      setSelectedAction(null);
    }
  }, [selectedTool]);

  // Get available actions for the selected tool
  const getAvailableActions = (toolKey) => {
    if (!toolKey) return [];
    const availableActionKeys = toolActionMap[toolKey] || [];
    return allActionTypes.filter((action) =>
      availableActionKeys.includes(action.key)
    );
  };

  const handleStart = async () => {
    if (!selectedTool || !selectedAction) {
      notifyError("Please select both tool and action");
      return;
    }

    setLogs([]);
    setLoading(true);
    const newSessionId = `${Date.now()}-${Math.random()
      .toString(36)
      .substring(2, 15)}`;

    const websocket_backend_url = process.env.REACT_APP_WEBSOCKET_URL;
    const webSocketURL = `${websocket_backend_url}/kubernetes-script-logs?session_id=${newSessionId}`;

    const ws = new WebSocket(webSocketURL);
    setSocket(ws);

    ws.onopen = async () => {
      const actionLabel =
        allActionTypes.find((a) => a.key === selectedAction)?.label ||
        selectedAction;
      const toolLabel =
        setupOptions.find((t) => t.key === selectedTool)?.label || selectedTool;
      appendLog(`Starting ${toolLabel} ${actionLabel.toLowerCase()}...`);

      try {
        const payload = {
          cluster_name: clusterName,
          username: localStorage.getItem("username"),
          region: clusterData.region,
          tool: selectedTool,
          action: selectedAction,
          ws_id: newSessionId,
        };

        if (
          !payload.cluster_name ||
          !payload.region ||
          !payload.tool ||
          !payload.action
        ) {
          notifyError("Some Error occurred");
          return;
        }

        if (!payload.username) {
          notifyError("Please login first");
          navigate("/login");
          return;
        }

        const res = await fetch(`${backend_url}/api/setup-kubernetes-tool`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const resText = await res.text();
        let result;
        try {
          result = JSON.parse(resText);
        } catch (e) {
          console.error("Failed to parse JSON:", resText);
          notifyError("Unexpected server response");
          setLoading(false);
          ws.close();
          return;
        }

        if (result.status !== "ok") {
          notifyError(`${actionLabel} failed`);
          appendLog(
            `${toolLabel} ${actionLabel.toLowerCase()} failed: ${result.error_message || result.detail || "Unknown error"
            }`
          );
          ws.close();
          setLoading(false);
          if (result?.fail_type || "" === "contact_us") {
            notifyRedirectToContact(navigate, 5);
          }
          return;
        } else {
          notifySuccess(`${actionLabel} successful`);
        }
      } catch (err) {
        appendLog(
          `${toolLabel} ${actionLabel.toLowerCase()} error: ${err.message}`
        );
        notifyError(`Error during ${actionLabel.toLowerCase()}`);
        ws.close();
        setLoading(false);
      }
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        // console.log("got this log: ", data);
        if (data.message && data.message.trim()) {
          const html = ansiConverter.toHtml(data.message);
          if (data.message == "setup completed") {
            const actionLabel =
              allActionTypes.find((a) => a.key === selectedAction)?.label ||
              selectedAction;
            // notifySuccess(`${actionLabel} completed`);
            setLoading(false);
            ws.close();
            setSocket(null);
          } else {
            appendHtmlLog(html);
          }
        }
      } catch {
        if (event.data.trim()) {
          const html = ansiConverter.toHtml(event.data);
          appendHtmlLog(html);
          if (event.data.includes("setup completed")) {
            const actionLabel =
              allActionTypes.find((a) => a.key === selectedAction)?.label ||
              selectedAction;
            notifySuccess(`${actionLabel} completed`);
            setLoading(false);
          }
        }
      }
    };

    ws.onerror = () => {
      appendLog("WebSocket error occurred.");
      notifyError("WebSocket connection error.");
      setLoading(false);
    };

    ws.onclose = () => {
      setLoading(false);
    };
  };

  const appendLog = (line) => {
    const html = ansiConverter.toHtml(line);
    setLogs((prev) => [...prev, html]);
  };

  const appendHtmlLog = (html) => {
    setLogs((prev) => [...prev, html]);
  };

  // Reset selections when modal closes
  useEffect(() => {
    if (!visible) {
      setSelectedTool(null);
      setSelectedAction(null);
      setLogs([]);
    }
  }, [visible]);

  useEffect(() => {
    if (!visible) return;
    return () => {
      if (socket) {
        socket.close();
      }
    };
  }, [socket, visible]);

  const toolOptions = setupOptions.map(({ label, key }) => ({
    label: (
      <div className="flex items-center gap-2 py-1">
        <div className="w-2 h-2 bg-indigo-500 rounded-full"></div>
        <span>{label}</span>
      </div>
    ),
    value: key,
  }));

  const availableActions = getAvailableActions(selectedTool);
  const actionOptions = availableActions.map(
    ({ label, key, icon: Icon, color }) => ({
      label: (
        <div className="flex items-center gap-2 py-1">
          <Icon className="w-4 h-4" style={{ color }} />
          <span>{label}</span>
        </div>
      ),
      value: key,
    })
  );

  return (
    <Modal
      title={
        <div className="flex items-center gap-3">
          <div className="w-2 h-10 bg-gradient-to-b from-indigo-600 to-purple-600 rounded-full"></div>
          <div>
            <h2 className="text-xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
              Cluster Setup
            </h2>
            <p className="text-m text-slate-700 dark:text-slate-400 font-normal">
              {clusterName}
            </p>
          </div>
        </div>
      }
      open={visible}
      onCancel={onClose}
      footer={null}
      width="85vw"
      styles={{
        body: {
          padding: 0,
          height: "70vh",
          overflow: "hidden",
        },
      }}
      style={{
        height: "80vh",
        maxHeight: "80vh",
        top: "10vh",
      }}
      className="cluster-setup-modal"
      getContainer={false}
    >
      <div className="h-full flex flex-col p-4">
        {/* Control Panel */}
        <div className="flex-shrink-0 mb-6">
          <div className="bg-transparent dark:bg-slate-900/80 backdrop-blur-lg rounded-xl shadow-lg shadow-indigo-500/10 px-6 py-4 border border-slate-200 dark:border-slate-700">
            <h3 className="text-lg font-semibold text-slate-500 dark:text-white mb-4">
              Select Tool & Action
            </h3>

            <div className="flex items-center gap-4 flex-wrap">
              {/* Tool Dropdown */}
              <div className="flex-1 min-w-[200px]">
                <label className="block text-sm font-medium text-slate-600 dark:text-slate-300 mb-2">
                  Choose Tool
                </label>
                <Select
                  placeholder="Select a tool..."
                  value={selectedTool}
                  onChange={setSelectedTool}
                  options={groupedToolOptions}
                  className="w-full"
                  size="large"
                  style={{ minWidth: 200 }}
                />
              </div>

              {/* Action Dropdown */}
              <div className="flex-1 min-w-[200px]">
                <label className="block text-sm font-medium text-slate-600 dark:text-slate-300 mb-2">
                  Choose Action
                </label>
                <Select
                  placeholder={
                    selectedTool ? "Select an action..." : "Select a tool first"
                  }
                  value={selectedAction}
                  onChange={setSelectedAction}
                  options={actionOptions}
                  className="w-full"
                  size="large"
                  style={{ minWidth: 200 }}
                  disabled={!selectedTool}
                />
              </div>

              {/* Start Button */}
              <div className="flex-shrink-0">
                <label className="block text-sm font-medium text-transparent mb-2">
                  Action
                </label>
                <Button
                  type="primary"
                  size="large"
                  loading={loading}
                  onClick={handleStart}
                  disabled={!selectedTool || !selectedAction}
                  className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 border-0 font-semibold px-8 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105 disabled:opacity-70 disabled:text-white"
                  icon={!loading && <Play className="w-4 h-4" />}
                >
                  {loading ? "Running..." : "Start"}
                </Button>
              </div>
            </div>
          </div>
        </div>

        {/* Logs Section */}
        <div className="flex-1 flex flex-col min-h-0">
          {/* Log Container*/}
          <div
            className="bg-slate-900 text-sm font-mono p-4 rounded-xl border border-slate-700 shadow-lg shadow-indigo-500/10 flex-1 overflow-y-auto whitespace-pre-wrap"
            style={{
              color: "#e2e8f0",
              minHeight: 0,
            }}
          >
            {logs.length === 0 ? (
              <div className="text-slate-500 italic text-center py-12 flex flex-col items-center gap-3 h-full justify-center">
                <div className="w-16 h-16 border-2 border-slate-700 rounded-full flex items-center justify-center">
                  <Settings className="w-8 h-8 text-slate-600" />
                </div>
                <div>
                  <p className="text-lg mb-1">Ready to execute</p>
                  <p className="text-sm">
                    Select a tool and action, then click Start to view live
                    logs...
                  </p>
                </div>
              </div>
            ) : (
              <>
                {logs.map((line, index) => (
                  <div key={index} dangerouslySetInnerHTML={{ __html: line }} />
                ))}
                <div ref={logEndRef} />
              </>
            )}
          </div>
        </div>
      </div>
    </Modal>
  );
};

export default ClusterSetupModal;
