import { COMPLIANCE_FRAMEWORKS } from "../../utils/complianceConfig";

const SIDEBAR_KEYS = [
  "gdpr", "pcidss", "hipaa", "soc2", "fedramp", "cis", "iso42001", "owasp",
  "nist", "nist80053", "iso27001", "iso27018", "dpdp", "rbi", "sebi", "ndhm", "ehr",
];

const FrameworkCard = ({ fw, onNavigate }) => (
  <div
    onClick={() => onNavigate(`compliance-${fw.key}`)}
    className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-lg shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700 p-6 hover:shadow-xl transition-all duration-200 hover:scale-[1.02] cursor-pointer group"
  >
    <div className="flex items-center gap-3 mb-3">
      <span className="text-3xl">{fw.icon}</span>
      <div>
        <h3 className="text-lg font-bold bg-gradient-to-r from-indigo-600 to-indigo-700 bg-clip-text text-transparent">
          {fw.label}
        </h3>
        <p className="text-xs text-slate-400 dark:text-slate-500">{fw.fullName}</p>
      </div>
    </div>

    <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed mb-4">
      {fw.simpleExplanation}
    </p>

    <div className="space-y-2 mb-4">
      <div className="flex items-start gap-2">
        <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap mt-0.5">Who needs it:</span>
        <span className="text-xs text-slate-600 dark:text-slate-300">{fw.whoNeedsIt}</span>
      </div>
      <div className="flex items-start gap-2">
        <span className="text-xs font-semibold text-slate-500 dark:text-slate-400 whitespace-nowrap mt-0.5">Key focus:</span>
        <span className="text-xs text-slate-600 dark:text-slate-300">{fw.keyFocus}</span>
      </div>
    </div>

    <div className="text-sm font-semibold bg-gradient-to-r from-indigo-600 to-indigo-700 bg-clip-text text-transparent group-hover:underline">
      View Findings →
    </div>
  </div>
);

const ComplianceLanding = ({ setSelectedMenu }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-indigo-700 bg-clip-text text-transparent">
              Compliance Frameworks
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-2 max-w-2xl">
              Compliance frameworks are sets of rules and best practices that help organizations protect data, 
              manage risk, and meet legal requirements. Choose a framework below to scan your AWS infrastructure 
              and assess compliance posture.
            </p>
          </div>

          <div className="mt-6 border-t border-gray-200 dark:border-gray-700 mb-8" />

          {/* Framework cards grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {SIDEBAR_KEYS.map((key) => {
              const fw = COMPLIANCE_FRAMEWORKS[key];
              if (!fw) return null;
              return (
                <FrameworkCard
                  key={key}
                  fw={fw}
                  onNavigate={setSelectedMenu}
                />
              );
            })}
          </div>

          {/* Bottom note */}
          <div className="mt-10 bg-white/60 dark:bg-slate-900/60 backdrop-blur-lg rounded-xl p-6 border border-indigo-100 dark:border-slate-700">
            <p className="text-sm text-slate-500 dark:text-slate-400">
              <span className="font-semibold text-slate-700 dark:text-slate-300">Not sure which framework to start with?</span>{" "}
              Check the <span className="font-medium text-indigo-600 dark:text-indigo-400 cursor-pointer hover:underline" onClick={() => setSelectedMenu("industry")}>Industry-Based</span> section — 
              it recommends the right frameworks based on your business type (Healthcare, Finance, SaaS, Government, or E-commerce).
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ComplianceLanding;
