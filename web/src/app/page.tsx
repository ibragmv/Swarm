"use client";

export default function DashboardPage() {
  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold">Dashboard</h2>
          <p className="text-gray-500 text-sm mt-1">
            Overview of all penetration testing activity
          </p>
        </div>
        <button className="px-4 py-2 bg-accent text-black font-medium rounded-lg hover:bg-accent/90 transition-colors">
          New Scan
        </button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-4 gap-4">
        <KPICard title="Total Campaigns" value="0" trend="+0%" />
        <KPICard title="Active Scans" value="0" active />
        <KPICard
          title="Total Findings"
          value="0"
          subtitle="0 critical, 0 high"
        />
        <KPICard title="Avg Scan Time" value="--" subtitle="no data yet" />
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-3 gap-6">
        {/* Active Campaigns */}
        <div className="col-span-2 bg-surface rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium text-gray-400 mb-4">
            Active Campaigns
          </h3>
          <div className="text-center py-12 text-gray-600">
            <p className="text-lg">No campaigns yet</p>
            <p className="text-sm mt-2">
              Run{" "}
              <code className="bg-background px-2 py-1 rounded text-accent">
                pentestswarm scan target.com --scope target.com
              </code>
            </p>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="bg-surface rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium text-gray-400 mb-4">
            Recent Activity
          </h3>
          <div className="space-y-3">
            <p className="text-sm text-gray-600">No recent activity</p>
          </div>
        </div>
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-2 gap-6">
        {/* Findings over time */}
        <div className="bg-surface rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium text-gray-400 mb-4">
            Findings Over Time
          </h3>
          <div className="h-48 flex items-center justify-center text-gray-600">
            Chart will render here with campaign data
          </div>
        </div>

        {/* Severity distribution */}
        <div className="bg-surface rounded-lg border border-border p-4">
          <h3 className="text-sm font-medium text-gray-400 mb-4">
            Severity Distribution
          </h3>
          <div className="h-48 flex items-center justify-center text-gray-600">
            Donut chart will render here
          </div>
        </div>
      </div>
    </div>
  );
}

function KPICard({
  title,
  value,
  subtitle,
  trend,
  active,
}: {
  title: string;
  value: string;
  subtitle?: string;
  trend?: string;
  active?: boolean;
}) {
  return (
    <div className="bg-surface rounded-lg border border-border p-4">
      <p className="text-xs text-gray-500 uppercase tracking-wide">{title}</p>
      <div className="flex items-baseline gap-2 mt-2">
        <p className="text-2xl font-bold">{value}</p>
        {trend && (
          <span className="text-xs text-green-400">{trend}</span>
        )}
        {active && (
          <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
        )}
      </div>
      {subtitle && <p className="text-xs text-gray-600 mt-1">{subtitle}</p>}
    </div>
  );
}
