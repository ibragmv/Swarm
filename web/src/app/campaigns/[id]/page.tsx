"use client";

import { useParams } from "next/navigation";

export default function CampaignLivePage() {
  const params = useParams();
  const id = params.id as string;

  return (
    <div className="h-full flex flex-col">
      {/* Phase Progress Bar */}
      <div className="bg-surface border-b border-border px-6 py-3">
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-400">Campaign {id}</span>
          <span className="text-gray-600">·</span>
          <PhaseStep label="Recon" active />
          <Arrow />
          <PhaseStep label="Classify" />
          <Arrow />
          <PhaseStep label="Plan" />
          <Arrow />
          <PhaseStep label="Execute" />
          <Arrow />
          <PhaseStep label="Report" />
        </div>
      </div>

      {/* Main panels */}
      <div className="flex-1 grid grid-cols-3 gap-0 overflow-hidden">
        {/* Agent Activity (left) */}
        <div className="col-span-1 border-r border-border overflow-y-auto p-4 space-y-3">
          <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wide">
            Agent Activity
          </h3>
          <AgentCard name="Orchestrator" status="active" detail="Planning campaign..." />
          <AgentCard name="Recon Agent" status="idle" detail="Waiting for dispatch" />
          <AgentCard name="Classifier" status="idle" detail="Waiting for findings" />
          <AgentCard name="Exploit Agent" status="idle" detail="Waiting for plan" />
          <AgentCard name="Report Agent" status="idle" detail="Waiting for completion" />
        </div>

        {/* Center: Attack Surface / Attack Paths (tabs) */}
        <div className="col-span-1 border-r border-border overflow-y-auto p-4">
          <div className="flex gap-4 mb-4">
            <button className="text-xs font-medium text-accent border-b-2 border-accent pb-1">
              Attack Surface
            </button>
            <button className="text-xs font-medium text-gray-500 pb-1 hover:text-gray-300">
              Attack Paths
            </button>
            <button className="text-xs font-medium text-gray-500 pb-1 hover:text-gray-300">
              MITRE ATT&CK
            </button>
          </div>
          <div className="h-96 bg-background rounded-lg border border-border flex items-center justify-center text-gray-600">
            Force-directed graph renders here
          </div>
        </div>

        {/* Right: Findings */}
        <div className="col-span-1 overflow-y-auto p-4">
          <h3 className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-3">
            Findings
          </h3>
          {/* Severity histogram */}
          <div className="flex gap-1 mb-4">
            <SeverityBar label="C" count={0} color="bg-severity-critical" />
            <SeverityBar label="H" count={0} color="bg-severity-high" />
            <SeverityBar label="M" count={0} color="bg-severity-medium" />
            <SeverityBar label="L" count={0} color="bg-severity-low" />
          </div>
          <p className="text-sm text-gray-600">
            No findings yet — waiting for scan to begin
          </p>
        </div>
      </div>

      {/* Bottom: Metrics Bar */}
      <div className="bg-surface border-t border-border px-6 py-2 flex items-center gap-8 text-xs text-gray-500">
        <span>Findings: <strong className="text-white">0</strong></span>
        <span>Tokens: <strong className="text-white">0</strong></span>
        <span>Elapsed: <strong className="text-white">0:00</strong></span>
        <span>Assets: <strong className="text-white">0</strong></span>
        <div className="flex-1" />
        <button className="px-3 py-1 bg-red-500/20 text-red-400 rounded border border-red-500/30 hover:bg-red-500/30 transition-colors">
          Emergency Stop
        </button>
      </div>
    </div>
  );
}

function PhaseStep({ label, active, done }: { label: string; active?: boolean; done?: boolean }) {
  const base = "text-xs px-2 py-1 rounded";
  if (done) return <span className={`${base} bg-green-500/20 text-green-400`}>{label} ✓</span>;
  if (active) return <span className={`${base} bg-accent/20 text-accent animate-pulse`}>{label}</span>;
  return <span className={`${base} text-gray-600`}>{label}</span>;
}

function Arrow() {
  return <span className="text-gray-600 text-xs">→</span>;
}

function AgentCard({ name, status, detail }: { name: string; status: "active" | "idle" | "complete" | "error"; detail: string }) {
  const borderClass = status === "active" ? "border-accent/50 agent-active" : "border-border";
  const statusColor = {
    active: "bg-accent",
    idle: "bg-gray-600",
    complete: "bg-green-500",
    error: "bg-red-500",
  }[status];

  return (
    <div className={`bg-background rounded-lg border ${borderClass} p-3`}>
      <div className="flex items-center gap-2">
        <span className={`w-2 h-2 rounded-full ${statusColor}`} />
        <span className="text-sm font-medium">{name}</span>
      </div>
      <p className="text-xs text-gray-500 mt-1 terminal-text">{detail}</p>
    </div>
  );
}

function SeverityBar({ label, count, color }: { label: string; count: number; color: string }) {
  return (
    <div className="flex flex-col items-center gap-1">
      <div className={`w-8 h-1 rounded ${color} opacity-30`} />
      <span className="text-[10px] text-gray-600">{label}: {count}</span>
    </div>
  );
}
