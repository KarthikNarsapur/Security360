import { INDUSTRY_CONFIG, COMPLIANCE_FRAMEWORKS } from "../../utils/complianceConfig";

const TIER_CONFIG = {
  mandatory: {
    label: "MANDATORY",
    badge: "Required",
    badgeClass: "bg-red-100 text-red-700 border-red-200",
    borderClass: "border-red-200 dark:border-red-800",
    dotColor: "bg-red-500",
  },
  recommended: {
    label: "RECOMMENDED",
    badge: "Recommended",
    badgeClass: "bg-amber-100 text-amber-700 border-amber-200",
    borderClass: "border-amber-200 dark:border-amber-800",
    dotColor: "bg-amber-500",
  },
  optional: {
    label: "OPTIONAL",
    badge: "Optional",
    badgeClass: "bg-gray-100 text-gray-600 border-gray-200",
    borderClass: "border-gray-200 dark:border-gray-700",
    dotColor: "bg-gray-400",
  },
};

const FrameworkCard = ({ frameworkKey, tier, onNavigate }) => {
  const fw = COMPLIANCE_FRAMEWORKS[frameworkKey];
  if (!fw) return null;

  const tierCfg = TIER_CONFIG[tier];

  return (
    <div
      className={`bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-lg shadow-indigo-500/10 border-2 ${tierCfg.borderClass} p-6 hover:shadow-xl transition-all duration-200 hover:scale-[1.02] flex flex-col justify-between`}
    >
      <div>
        <div className="flex items-center justify-between mb-3">
          <span className="text-2xl">{fw.icon}</span>
          <span
            className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${tierCfg.badgeClass}`}
          >
            {tierCfg.badge}
          </span>
        </div>
        <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-1">
          {fw.label}
        </h3>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-1">
          {fw.fullName}
        </p>
        <p className="text-xs text-slate-400 dark:text-slate-500">
          {fw.description}
        </p>
      </div>
      <button
        onClick={() => onNavigate(`compliance-${frameworkKey}`)}
        className="mt-4 w-full py-2 px-4 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-indigo-700 hover:shadow-lg transition-all duration-200 hover:scale-105"
      >
        View Findings →
      </button>
    </div>
  );
};

const IndustryDashboard = ({ industryKey, setSelectedMenu }) => {
  // If no specific industry selected, show all industries as a landing page
  if (!industryKey) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
        <div className="p-6 pl-12">
          <div className="max-w-7xl mx-auto">
            <div className="mb-8">
              <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-indigo-700 bg-clip-text text-transparent">
                Industry-Based Compliance
              </h1>
              <p className="text-sm text-slate-500 dark:text-slate-400 mt-2 max-w-2xl">
                Not sure which compliance frameworks apply to your business? Select your industry below 
                and we will show you the mandatory, recommended, and optional frameworks for your sector.
              </p>
            </div>
            <div className="mt-6 border-t border-gray-200 dark:border-gray-700 mb-8" />
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {Object.entries(INDUSTRY_CONFIG).map(([key, ind]) => (
                <div
                  key={key}
                  onClick={() => setSelectedMenu(`industry-${key}`)}
                  className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-lg shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700 p-8 hover:shadow-xl transition-all duration-200 hover:scale-[1.02] cursor-pointer text-center"
                >
                  <div className="text-5xl mb-4">{ind.icon}</div>
                  <h3 className="text-xl font-bold bg-gradient-to-r from-indigo-600 to-indigo-700 bg-clip-text text-transparent mb-2">
                    {ind.label}
                  </h3>
                  <p className="text-sm text-slate-500 dark:text-slate-400">{ind.description}</p>
                  <div className="mt-4 text-xs text-slate-400 dark:text-slate-500">
                    {ind.frameworks.mandatory.length} mandatory · {ind.frameworks.recommended.length} recommended · {ind.frameworks.optional.length} optional
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const industry = INDUSTRY_CONFIG[industryKey];

  if (!industry) {
    return (
      <div className="p-12 text-red-500">Unknown industry: {industryKey}</div>
    );
  }

  const { mandatory = [], recommended = [], optional = [] } = industry.frameworks;

  const renderTier = (tier, keys) => {
    if (!keys.length) return null;
    const tierCfg = TIER_CONFIG[tier];
    return (
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-4">
          <span className={`w-3 h-3 rounded-full ${tierCfg.dotColor}`} />
          <h2 className="text-lg font-bold text-slate-700 dark:text-slate-300 tracking-wide">
            {tierCfg.label}
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {keys.map((fwKey) => (
            <FrameworkCard
              key={fwKey}
              frameworkKey={fwKey}
              tier={tier}
              onNavigate={setSelectedMenu}
            />
          ))}
        </div>
      </div>
    );
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950">
      <div className="p-6 pl-12">
        <div className="max-w-7xl mx-auto">
          <div className="mb-8">
            <h1 className="text-3xl font-bold bg-gradient-to-r from-indigo-600 to-indigo-700 bg-clip-text text-transparent">
              {industry.label}
            </h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">
              {industry.description}
            </p>
          </div>

          <div className="mt-6 border-t border-gray-200 dark:border-gray-700 mb-8" />

          {renderTier("mandatory", mandatory)}
          {renderTier("recommended", recommended)}
          {renderTier("optional", optional)}
        </div>
      </div>
    </div>
  );
};

export default IndustryDashboard;
