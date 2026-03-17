import * as vscode from "vscode";

let statusBarItem: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext) {
  console.log("autopentest extension activated");

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.text = "$(shield) autopentest";
  statusBarItem.tooltip = "AutoPentest — AI Penetration Testing";
  statusBarItem.command = "autopentest.scan";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("autopentest.scan", scanTarget),
    vscode.commands.registerCommand("autopentest.explain", explainFinding),
    vscode.commands.registerCommand("autopentest.stop", stopCampaign),
    vscode.commands.registerCommand("autopentest.viewReport", viewReport)
  );

  // Findings tree view
  const findingsProvider = new FindingsTreeProvider();
  vscode.window.registerTreeDataProvider(
    "autopentest.findings",
    findingsProvider
  );

  // Diagnostics collection (shows findings in Problems panel)
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("autopentest");
  context.subscriptions.push(diagnosticCollection);
}

export function deactivate() {
  statusBarItem?.dispose();
}

// --- Commands ---

async function scanTarget() {
  const target = await vscode.window.showInputBox({
    prompt: "Enter target domain or IP",
    placeHolder: "example.com",
  });

  if (!target) return;

  const scope = await vscode.window.showInputBox({
    prompt: "Enter scope (domain or CIDR)",
    placeHolder: target,
    value: target,
  });

  if (!scope) return;

  statusBarItem.text = "$(loading~spin) Scanning...";

  try {
    const config = vscode.workspace.getConfiguration("autopentest");
    const apiUrl = config.get<string>("apiUrl", "http://localhost:8080");

    const response = await fetch(`${apiUrl}/api/v1/campaigns`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target,
        scope: { allowed_domains: [scope] },
        objective: "find all vulnerabilities",
      }),
    });

    const data = (await response.json()) as { id: string };

    // Start the campaign
    await fetch(`${apiUrl}/api/v1/campaigns/${data.id}/start`, {
      method: "POST",
    });

    vscode.window.showInformationMessage(
      `Campaign started: ${data.id}. Findings will appear in the Problems panel.`
    );

    // Poll for findings (in production, use WebSocket)
    pollFindings(apiUrl, data.id);
  } catch (err) {
    vscode.window.showErrorMessage(
      `Failed to start scan: ${err}. Is autopentest serve running?`
    );
    statusBarItem.text = "$(shield) autopentest";
  }
}

async function explainFinding() {
  const findingId = await vscode.window.showInputBox({
    prompt: "Enter finding ID or CVE ID",
    placeHolder: "CVE-2024-1234",
  });

  if (!findingId) return;

  const config = vscode.workspace.getConfiguration("autopentest");
  const apiUrl = config.get<string>("apiUrl", "http://localhost:8080");

  try {
    const response = await fetch(
      `${apiUrl}/api/v1/explain/${encodeURIComponent(findingId)}`
    );
    const data = (await response.json()) as { explanation: string };

    const doc = await vscode.workspace.openTextDocument({
      content: data.explanation,
      language: "markdown",
    });
    vscode.window.showTextDocument(doc, { preview: true });
  } catch (err) {
    vscode.window.showErrorMessage(`Failed to explain: ${err}`);
  }
}

async function stopCampaign() {
  vscode.window.showInformationMessage("Campaign stopped.");
  statusBarItem.text = "$(shield) autopentest";
}

async function viewReport() {
  vscode.window.showInformationMessage(
    "Report viewer: run autopentest campaign report <id>"
  );
}

// --- Findings Polling ---

async function pollFindings(apiUrl: string, campaignId: string) {
  const diagnosticCollection =
    vscode.languages.createDiagnosticCollection("autopentest");

  // Poll every 10 seconds for new findings
  const interval = setInterval(async () => {
    try {
      const response = await fetch(
        `${apiUrl}/api/v1/campaigns/${campaignId}/findings`
      );
      const data = (await response.json()) as {
        data: Array<{
          title: string;
          severity: string;
          target: string;
          description: string;
        }>;
      };

      if (data.data && data.data.length > 0) {
        // Show findings in Problems panel
        const diagnostics: vscode.Diagnostic[] = data.data.map((finding) => {
          const severity = mapSeverity(finding.severity);
          const range = new vscode.Range(0, 0, 0, 0);
          const diag = new vscode.Diagnostic(
            range,
            `[${finding.severity.toUpperCase()}] ${finding.title}: ${finding.description}`,
            severity
          );
          diag.source = "autopentest";
          return diag;
        });

        const uri = vscode.Uri.parse(`autopentest://${campaignId}`);
        diagnosticCollection.set(uri, diagnostics);

        statusBarItem.text = `$(shield) ${data.data.length} findings`;
      }

      // Check if campaign is complete
      const statusResp = await fetch(
        `${apiUrl}/api/v1/campaigns/${campaignId}`
      );
      const statusData = (await statusResp.json()) as { status: string };
      if (
        statusData.status === "complete" ||
        statusData.status === "failed" ||
        statusData.status === "aborted"
      ) {
        clearInterval(interval);
        statusBarItem.text = "$(shield) autopentest";
        vscode.window.showInformationMessage(
          `Campaign ${statusData.status}. ${data.data?.length || 0} findings.`
        );
      }
    } catch {
      // Silently retry
    }
  }, 10000);
}

function mapSeverity(
  severity: string
): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

// --- Tree View ---

class FindingsTreeProvider
  implements vscode.TreeDataProvider<vscode.TreeItem>
{
  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(): vscode.TreeItem[] {
    return [
      new vscode.TreeItem(
        "No findings yet — run a scan",
        vscode.TreeItemCollapsibleState.None
      ),
    ];
  }
}
