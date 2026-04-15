"use client";

import { Button } from "antd";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import {
  BadgeCheck,
  ShieldCheck,
  Activity,
  Network,
  Container,
  Settings,
  Eye,
  Download,
} from "lucide-react";

function WelcomePage() {
  const navigate = useNavigate();

  const handleGetStarted = () => {
    navigate("/signup");
  };

  const fadeInUp = {
    hidden: { opacity: 0, y: 40 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.6 } },
  };

  const fadeIn = {
    hidden: { opacity: 0 },
    visible: { opacity: 1, transition: { duration: 0.8 } },
  };

  const infraFeatures = [
    {
      icon: <ShieldCheck className="w-6 h-6" />,
      text: "Real-time threat detection, intelligence, and response for cloud-native workloads",
    },
    {
      icon: <BadgeCheck className="w-6 h-6" />,
      text: "Enforce AWS security best practices and get continuous compliance reports",
    },
    {
      icon: <Activity className="w-6 h-6" />,
      text: "Detect unusual behavior using machine learning and get instant alerts",
    },
    {
      icon: <Network className="w-6 h-6" />,
      text: "Add AWS accounts easily and run automated scans without any coding",
    },
  ];

  const eksFeatures = [
    {
      icon: <Container className="w-6 h-6" />,
      text: "List and manage all EKS clusters with comprehensive security tooling",
    },
    {
      icon: <Settings className="w-6 h-6" />,
      text: "Install, debug, and remove security tools like ArgoCD, Falco, and Gatekeeper",
    },
    {
      icon: <Eye className="w-6 h-6" />,
      text: "Monitor live logs from security tools directly in the UI with real-time updates",
    },
    {
      icon: <Download className="w-6 h-6" />,
      text: "Generate and download comprehensive security reports in PDF format",
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <main className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-indigo-600/10 to-purple-600/10 dark:from-indigo-400/5 dark:to-purple-400/5"></div>
        <div className="relative px-8 py-10">
          <motion.div
            className="max-w-4xl mx-auto text-center"
            initial="hidden"
            animate="visible"
            variants={fadeIn}
          >
            <motion.h1
              className="pb-2 text-6xl font-bold bg-gradient-to-r from-indigo-600 via-purple-600 to-indigo-800 dark:from-indigo-400 dark:via-purple-400 dark:to-indigo-300 bg-clip-text text-transparent mb-6"
              variants={fadeInUp}
            >
              Security360
            </motion.h1>

            <motion.p
              className="text-xl text-slate-600 dark:text-slate-300 mb-12 max-w-2xl mx-auto leading-relaxed"
              variants={fadeInUp}
            >
              Comprehensive cloud security platform that protects your AWS
              infrastructure and EKS clusters with intelligent threat detection,
              automated compliance monitoring, and complete Kubernetes security
              management.
            </motion.p>

            <motion.div
              className="flex flex-col sm:flex-row gap-4 justify-center mb-12"
              variants={fadeInUp}
            >
              <Button
                onClick={handleGetStarted}
                className="!bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-700 hover:to-indigo-800 text-white hover:!text-white border-0 font-semibold px-8 py-3 h-auto rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-105"
                size="large"
              >
                Get Started
              </Button>
            </motion.div>

            {/* Infrastructure Security */}
            <motion.div
              className="mb-12"
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              variants={fadeIn}
            >
              <h3 className="text-xl font-semibold text-indigo-600 dark:text-indigo-400 mb-6 flex items-center justify-center gap-2">
                <ShieldCheck className="w-5 h-5" />
                AWS Infrastructure Security
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
                {infraFeatures.map((feature, index) => (
                  <motion.div
                    key={index}
                    className="flex items-start gap-4 p-6 bg-white/60 dark:bg-slate-800/60 backdrop-blur-lg rounded-2xl shadow-lg"
                    variants={fadeInUp}
                    whileHover={{ scale: 1.05 }}
                  >
                    <div className="flex-shrink-0 p-2 bg-gradient-to-r from-indigo-500 to-indigo-600 text-white rounded-xl">
                      {feature.icon}
                    </div>
                    <p className="text-slate-700 dark:text-slate-300 text-left leading-relaxed">
                      {feature.text}
                    </p>
                  </motion.div>
                ))}
              </div>
            </motion.div>

            {/* EKS Security */}
            <motion.div
              className="mb-12"
              initial="hidden"
              whileInView="visible"
              viewport={{ once: true }}
              variants={fadeIn}
            >
              <h3 className="text-xl font-semibold text-purple-600 dark:text-purple-400 mb-6 flex items-center justify-center gap-2">
                <Container className="w-5 h-5" />
                EKS Kubernetes Security
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-4xl mx-auto">
                {eksFeatures.map((feature, index) => (
                  <motion.div
                    key={index}
                    className="flex items-start gap-4 p-6 bg-white/60 dark:bg-slate-800/60 backdrop-blur-lg rounded-2xl shadow-lg"
                    variants={fadeInUp}
                    whileHover={{ scale: 1.05 }}
                  >
                    <div className="flex-shrink-0 p-2 bg-gradient-to-r from-purple-500 to-purple-600 text-white rounded-xl">
                      {feature.icon}
                    </div>
                    <p className="text-slate-700 dark:text-slate-300 text-left leading-relaxed">
                      {feature.text}
                    </p>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </motion.div>
        </div>
      </main>

      {/* Bottom Section */}
      <motion.section
        className="relative overflow-hidden"
        initial="hidden"
        whileInView="visible"
        viewport={{ once: true }}
        variants={fadeIn}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-indigo-600 to-purple-700 dark:from-indigo-800 dark:to-purple-900"></div>
        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent"></div>
        <div className="relative px-8 py-10">
          <div className="max-w-6xl mx-auto">
            <div className="grid md:grid-cols-2 gap-12 items-center">
              <motion.div variants={fadeInUp}>
                <p className="text-indigo-100 text-lg mb-8 leading-relaxed">
                  A unified security platform that protects both your AWS
                  infrastructure and EKS clusters in real time. From
                  infrastructure scanning to Kubernetes security tool
                  management, get comprehensive protection with live monitoring,
                  automated compliance, and detailed reporting — all through an
                  intuitive interface without writing any code.
                </p>
              </motion.div>

              <motion.div
                className="relative"
                variants={fadeInUp}
                whileHover={{ scale: 1.02 }}
              >
                <div className="text-center relative z-10">
                  <div className="text-8xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-white via-indigo-200 to-purple-200 leading-tight">
                    Cloud
                    <br />
                    +
                    <br />
                    K8s
                    <br />
                    Security
                  </div>
                </div>
                <div className="absolute inset-0 bg-gradient-to-r from-indigo-400/20 to-purple-400/20 blur-3xl"></div>
              </motion.div>
            </div>
          </div>
        </div>
      </motion.section>
    </div>
  );
}

export default WelcomePage;
