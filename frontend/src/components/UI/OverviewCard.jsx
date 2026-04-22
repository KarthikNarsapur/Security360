import { MdAccountCircle } from "react-icons/md";
import { BiSolidFileFind, BiSolidError } from "react-icons/bi";
import { SiAmazonwebservices } from "react-icons/si";
import { AiFillSecurityScan } from "react-icons/ai";

export default function OverviewCard({ findings, setSelectedMenu }) {
  const filteredFindings = findings.filter(
    (f) =>
      f.additional_info?.affected > 0 && f.additional_info?.total_scanned > 0
  );

  const totalFindings = filteredFindings.length;
  const uniqueResources = new Set(filteredFindings.flatMap((f) => f.check_name))
    .size;
  const uniqueAccounts = new Set(
    filteredFindings.map((f) => f.account_id || "account1")
  ).size;
  const totalScanned = filteredFindings.reduce(
    (acc, f) => acc + (f.additional_info?.total_scanned || 0),
    0
  );
  const affected = filteredFindings.reduce(
    (acc, f) => acc + (f.additional_info?.affected || 0),
    0
  );
  const percent = totalScanned
    ? ((affected / totalScanned) * 100).toFixed(2)
    : 0;

  const redirectCard = () => {
    setSelectedMenu("findings");
  };

  const cards = [
    {
      label: "Findings",
      value: totalFindings,
      onclick: () => redirectCard(),
      icon: <BiSolidFileFind />,
      color: "from-blue-600 to-blue-700",
      iconBg: "bg-gradient-to-r from-blue-600 to-blue-700",
    },
    {
      label: "Services",
      value: uniqueResources,
      icon: <SiAmazonwebservices />,
      color: "from-green-600 to-green-700",
      iconBg: "bg-gradient-to-r from-green-600 to-green-700",
    },
    {
      label: "Accounts",
      value: uniqueAccounts,
      icon: <MdAccountCircle />,
      color: "from-purple-600 to-purple-700",
      iconBg: "bg-gradient-to-r from-purple-600 to-purple-700",
    },
    {
      label: "Scanned",
      value: totalScanned,
      icon: <AiFillSecurityScan />,
      color: "from-indigo-600 to-indigo-700",
      iconBg: "bg-gradient-to-r from-indigo-600 to-indigo-700",
    },
    {
      label: "Affected",
      value: `${affected} (${percent}%)`,
      icon: <BiSolidError />,
      color: "from-red-600 to-red-700",
      iconBg: "bg-gradient-to-r from-red-600 to-red-700",
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
      {cards.map((card, index) => (
        <div
          key={index}
          className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 pb-4 border border-indigo-100 dark:border-slate-700 transition-all duration-300 hover:scale-105 hover:shadow-2xl hover:shadow-indigo-500/20 cursor-pointer animate-fade-in-up group flex flex-col items-center text-center"
          // style={{ animationDelay: `${index * 100}ms` }}
          onClick={card.onclick}
        >
          <div className="flex items-center justify-center gap-3 mb-4">
            <div
              className={`${card.iconBg} p-2 rounded-xl shadow-lg transition-transform duration-300 group-hover:scale-110`}
            >
              <div className="text-white text-xl">{card.icon}</div>
            </div>
            <p className="text-lg font-medium text-slate-600 dark:text-slate-400">
              {card.label}
            </p>
          </div>

          <p
            className={`text-3xl font-bold bg-gradient-to-r ${card.color} bg-clip-text text-transparent`}
          >
            {card.value}
          </p>
        </div>
      ))}
    </div>
  );
}
