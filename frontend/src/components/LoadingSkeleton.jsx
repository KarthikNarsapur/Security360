import Skeleton from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import {
  Shield,
  CheckCircle,
  XCircle,
  AlertTriangle,
  HelpCircle,
  X,
  Calendar,
  MapPin,
  Server,
  Database,
  Eye,
  ChevronRight,
  ChevronDown,
  Play,
  User,
  Clock,
  Loader2,
  Zap,
} from "lucide-react";

export const LoadingSkeletonSummaryPage = () => {
  const cards_count = 5;
  const graph_count = 3;

  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-5 lg:grid-cols-5 gap-4">
        {[...Array(cards_count)].map((_, i) => (
          <div
            key={i}
            className="bg-white rounded-xl shadow p-4 dark:bg-gray-800 transform transition duration-300 hover:scale-105"
          >
            <div className="flex justify-between items-start mb-1 min-h-[2.5rem]">
              <p>
                <Skeleton width={100} />
              </p>
              <div>
                <Skeleton circle={true} height={40} width={40} />
              </div>
            </div>
            <a>
              <Skeleton width={100} />
            </a>
          </div>
        ))}
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 lg:grid-cols-3 gap-6">
        {[...Array(graph_count)].map((_, i) => (
          <div className="mt-4">
            <div className="flex justify-between">
              <Skeleton width={300} height={400} />
            </div>
          </div>
        ))}
      </div>
    </>
  );
};

export const LoadingSkeletonThreatDetection = () => {
  const graph_count = 6;

  return (
    <>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {[...Array(graph_count)].map((_, i) => (
          <div key={i} className="mt-4">
            <div className="flex justify-between">
              <Skeleton width={300} height={150} />
            </div>
          </div>
        ))}
      </div>
    </>
  );
};

export const LoadingSkeletonFindingsTable = () => {
  const graph_count = 10;

  return (
    <>
      <div>
        {[...Array(graph_count)].map((_, i) => (
          <div className="mt-4">
            <div className="flex justify-between">
              <Skeleton width={1200} height={20} />
            </div>
          </div>
        ))}
      </div>
    </>
  );
};

export const LoadingSkeletonProfilePage = () => {
  return (
    <div className="p-10 bg-gray-100 dark:bg-gray-500 flex flex-col items-center">
      <div className="flex bg-white dark:bg-gray-700 min-h-[100px] w-[900px] relative pb-[100px] pt-16 before:absolute before:content-[''] before:left-0 before:top-0 before:w-full before:h-2 before:bg-gradient-to-r before:from-indigo-500 before:to-indigo-900 dark:before:from-gray-900 dark:before:to-gray-200">
        <div className="absolute left-20 transform bottom-[-100px] z-10 group">
          <div className="relative">
            <Skeleton className="max-h-[200px] max-w-[200px] min-h-[200px] min-w-[200px] rounded-lg mt-10" />
          </div>
        </div>
        <div className="w-full">
          <div className="pb-6 flex gap-2 absolute left-[300px] bottom-[-10px]">
            <Skeleton width={200} height={40} />
          </div>
        </div>
      </div>
      <div className="p-20 pt-36 bg-gray-200 dark:bg-gray-600 min-h-[100px] w-[900px]">
        <div className="flex gap-6 mb-4">
          <div className="flex items-center gap-2">
            <Skeleton circle={true} height={20} width={20} />
            <Skeleton width={150} height={24} />
          </div>
        </div>
        <div className="flex gap-6 mb-4">
          <div className="flex items-center gap-2">
            <Skeleton circle={true} height={20} width={20} />
            <Skeleton width={200} height={24} />
          </div>
        </div>
        <div className="h-[1px] bg-gray-300 dark:bg-gray-400 my-4" />
        <div className="flex gap-6 mb-4">
          <div className="flex items-center gap-2">
            <Skeleton circle={true} height={20} width={20} />
            <Skeleton width={180} height={24} />
          </div>
        </div>
        <div className="flex gap-6">
          <div className="flex items-center gap-2">
            <Skeleton circle={true} height={20} width={20} />
            <Skeleton width={150} height={24} />
          </div>
        </div>
        <div className="h-[1px] bg-gray-300 dark:bg-gray-400 my-4" />
        <div className="flex gap-6 mb-4">
          <div className="flex items-center gap-2">
            <Skeleton circle={true} height={20} width={20} />
            <Skeleton width={120} height={24} />
          </div>
        </div>
        <div className="flex gap-6 mb-4">
          <div className="flex items-center gap-2">
            <Skeleton circle={true} height={20} width={20} />
            <Skeleton width={80} height={24} />
          </div>
        </div>
      </div>
    </div>
  );
};

export const LoadingSkeletonCisDashboard = ({ progress = 0 }) => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 relative">
      {/* Progressive Loading Bar Overlay */}
      <div className="fixed inset-0 z-50 bg-black/20 backdrop-blur-sm flex items-center justify-center">
        <div className="bg-white/95 dark:bg-slate-900/95 backdrop-blur-lg rounded-3xl shadow-2xl p-8 border border-indigo-200 dark:border-slate-700 max-w-md w-full mx-4">
          <div className="text-center mb-6">
            <div className="relative inline-flex items-center justify-center w-16 h-16 mb-4">
              <div className="absolute inset-0 rounded-full bg-gradient-to-r from-indigo-500 to-purple-600 animate-spin">
                <div className="absolute inset-1 rounded-full bg-white dark:bg-slate-900"></div>
              </div>
              <Shield className="w-8 h-8 text-indigo-600 z-10" />
            </div>
            <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2">
              Scanning CIS Rules
            </h3>
            <p className="text-slate-600 dark:text-slate-400 text-sm">
              Analyzing security compliance across regions...
            </p>
          </div>

          {/* Creative Progress Bar */}
          <div className="relative mb-6">
            <div className="h-3 bg-gradient-to-r from-slate-200 to-slate-300 dark:from-slate-700 dark:to-slate-600 rounded-full overflow-hidden shadow-inner">
              <div
                className="h-full bg-gradient-to-r from-indigo-500 via-purple-500 to-pink-500 rounded-full transition-all duration-500 ease-out relative"
                style={{ width: `${progress}%` }}
              >
                <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-pulse"></div>
                <div className="absolute right-0 top-0 h-full w-8 bg-gradient-to-l from-white/40 to-transparent animate-pulse"></div>
              </div>
            </div>
            <div className="flex justify-between items-center mt-2">
              <span className="text-sm font-medium text-slate-600 dark:text-slate-400">
                Progress: {Math.round(progress)}%
              </span>
              <div className="flex items-center gap-1 text-indigo-600 dark:text-indigo-400">
                <Zap className="w-4 h-4" />
                <span className="text-sm font-medium">Scanning...</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Background Skeleton */}
      <div className="p-6">
        <div className="max-w-7xl mx-auto">
          {/* Header Skeleton */}
          <div className="mb-8">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 bg-slate-200 dark:bg-slate-700 rounded-lg animate-pulse"></div>
                <div className="w-64 h-8 bg-slate-200 dark:bg-slate-700 rounded-lg animate-pulse"></div>
              </div>
              <div className="flex items-center gap-4">
                <div className="w-80 h-10 bg-slate-200 dark:bg-slate-700 rounded-lg animate-pulse"></div>
                <div className="w-20 h-10 bg-slate-200 dark:bg-slate-700 rounded-lg animate-pulse"></div>
              </div>
            </div>
          </div>

          {/* Charts Skeleton */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl p-6 border border-indigo-100 dark:border-slate-700">
              <div className="w-48 h-6 bg-slate-200 dark:bg-slate-700 rounded animate-pulse mb-4"></div>
              <div className="w-64 h-64 bg-slate-200 dark:bg-slate-700 rounded-full animate-pulse mx-auto"></div>
            </div>
            <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl p-6 border border-indigo-100 dark:border-slate-700">
              <div className="w-48 h-6 bg-slate-200 dark:bg-slate-700 rounded animate-pulse mb-4"></div>
              <div className="space-y-4">
                {[1, 2, 3, 4].map((i) => (
                  <div
                    key={i}
                    className="w-full h-8 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"
                  ></div>
                ))}
              </div>
            </div>
          </div>

          {/* Cards Skeleton */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
            {[1, 2, 3, 4].map((i) => (
              <div
                key={i}
                className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl p-6 border border-indigo-100 dark:border-slate-700"
              >
                <div className="flex items-center justify-between">
                  <div className="space-y-2">
                    <div className="w-16 h-4 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>
                    <div className="w-12 h-8 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>
                  </div>
                  <div className="w-8 h-8 bg-slate-200 dark:bg-slate-700 rounded-full animate-pulse"></div>
                </div>
              </div>
            ))}
          </div>

          {/* Table Skeleton */}
          <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl border border-indigo-100 dark:border-slate-700">
            <div className="p-6 border-b border-indigo-100 dark:border-slate-700">
              <div className="w-48 h-6 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>
            </div>
            <div className="p-6">
              <div className="space-y-4">
                {[1, 2, 3, 4, 5].map((i) => (
                  <div key={i} className="flex items-center gap-4">
                    <div className="w-16 h-4 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>
                    <div className="w-20 h-4 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>
                    <div className="w-24 h-4 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>
                    <div className="flex-1 h-4 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>
                    <div className="w-32 h-4 bg-slate-200 dark:bg-slate-700 rounded animate-pulse"></div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export const LoadingSkeletonCisDashboardS3Fetch = () => {
  return (
    <div className="animate-fade-in-up p-6 bg-gradient-to-br from-slate-50 to-indigo-50 dark:from-slate-900 dark:to-indigo-950 min-h-screen">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <Skeleton circle={true} height={32} width={32} />
            <Skeleton width={300} height={36} className="rounded-lg" />
          </div>
        </div>

        {/* Top Row - Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Security Score Chart */}
          <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700">
            <Skeleton width={200} height={24} className="rounded-lg mb-4" />
            <div className="relative h-64 flex items-center justify-center">
              <Skeleton circle={true} height={200} width={200} />
            </div>
            <div className="mt-4 text-center">
              <Skeleton
                width={180}
                height={16}
                className="rounded-lg mx-auto"
              />
            </div>
          </div>

          {/* Severity Distribution */}
          <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700">
            <Skeleton width={220} height={24} className="rounded-lg mb-4" />
            <div className="h-64">
              <Skeleton width="100%" height={240} className="rounded-xl" />
            </div>
          </div>
        </div>

        {/* Overview Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          {[...Array(4)].map((_, i) => (
            <div
              key={i}
              className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 p-6 border border-indigo-100 dark:border-slate-700"
            >
              <div className="flex items-center justify-between">
                <div className="space-y-2">
                  <Skeleton width={80} height={16} className="rounded-lg" />
                  <Skeleton width={60} height={32} className="rounded-lg" />
                </div>
                <Skeleton circle={true} height={32} width={32} />
              </div>
            </div>
          ))}
        </div>

        {/* Findings Table */}
        <div className="bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg rounded-2xl shadow-xl shadow-indigo-500/10 border border-indigo-100 dark:border-slate-700">
          <div className="p-6 border-b border-indigo-100 dark:border-slate-700">
            <Skeleton width={180} height={24} className="rounded-lg" />
          </div>
          <div className="p-6">
            {/* Table Header */}
            <div className="grid grid-cols-5 gap-4 mb-4 pb-4 border-b border-slate-200 dark:border-slate-700">
              {[...Array(5)].map((_, i) => (
                <Skeleton
                  key={i}
                  width="80%"
                  height={20}
                  className="rounded-lg"
                />
              ))}
            </div>

            {/* Table Rows */}
            <div className="space-y-4">
              {[...Array(8)].map((_, i) => (
                <div key={i} className="grid grid-cols-5 gap-4 py-3">
                  <div className="flex items-center gap-2">
                    <Skeleton circle={true} height={16} width={16} />
                    <Skeleton width={80} height={20} className="rounded-lg" />
                  </div>
                  <Skeleton width={70} height={20} className="rounded-lg" />
                  <Skeleton width={100} height={20} className="rounded-lg" />
                  <Skeleton width="90%" height={20} className="rounded-lg" />
                  <Skeleton width={40} height={20} className="rounded-lg" />
                </div>
              ))}
            </div>

            {/* Pagination */}
            <div className="flex justify-between items-center mt-6 pt-4 border-t border-slate-200 dark:border-slate-700">
              <Skeleton width={150} height={20} className="rounded-lg" />
              <div className="flex gap-2">
                {[...Array(5)].map((_, i) => (
                  <Skeleton
                    key={i}
                    width={32}
                    height={32}
                    className="rounded-lg"
                  />
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export const ISOSummarySkeleton = () => {
  const cards_count = 4;
  const graph_count = 2;

  return (
    <div className="mt-6">
      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {[...Array(graph_count)].map((_, i) => (
          <div
            key={i}
            className="bg-white/80 dark:bg-gray-800 backdrop-blur-lg rounded-2xl shadow-lg p-6 border border-indigo-100 dark:border-slate-700"
          >
            <Skeleton height={24} width={180} className="mb-4" />
            <Skeleton height={250} />
          </div>
        ))}
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        {[...Array(cards_count)].map((_, i) => (
          <div
            key={i}
            className="bg-white/80 dark:bg-gray-800 backdrop-blur-lg rounded-2xl shadow-lg p-6 border border-indigo-100 dark:border-slate-700"
          >
            <Skeleton width={100} height={18} className="mb-2" />
            <Skeleton width={60} height={40} />
          </div>
        ))}
      </div>

      {/* Table Section */}
      <div className="bg-white/80 dark:bg-gray-800 rounded-2xl shadow-lg border border-indigo-100 dark:border-slate-700 p-6">
        <Skeleton height={24} width={220} className="mb-4" />
        {[...Array(8)].map((_, i) => (
          <Skeleton key={i} height={16} className="mb-3" />
        ))}
      </div>
    </div>
  );
};
