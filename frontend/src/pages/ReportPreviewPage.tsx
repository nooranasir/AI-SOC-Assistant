import Shell from '../components/Shell';
import Loader from '../components/Loader';
import { useWorkspace } from '../context/workspace';
import type { ReactElement } from 'react';

export default function ReportPreviewPage(): ReactElement {
  const { state } = useWorkspace();

  function handleDownload(): void {
    if (!state.report) {
      return;
    }
    const blob = new Blob([state.report.report_markdown], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `incident-report-${state.report.report_id}.md`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <Shell title="Incident Report Preview" subtitle="Preview the markdown report returned by the backend and download it locally.">
      <div className="panel card-block">
        {!state.report ? (
          <div className="empty-state">Run alert analysis to generate a report preview.</div>
        ) : (
          <>
            <div className="status-grid">
              <div className="info-card">
                <h4>Report ID</h4>
                <p>{state.report.report_id}</p>
              </div>
              <div className="info-card">
                <h4>Severity</h4>
                <p>{state.report.severity}</p>
              </div>
              <div className="info-card">
                <h4>Generated</h4>
                <p>{new Date(state.report.generated_at).toLocaleString()}</p>
              </div>
            </div>
            <Loader label="Report ready for review" />
            <pre className="code-block report-preview">{state.report.report_markdown}</pre>
            <button className="primary-button" type="button" onClick={handleDownload}>
              Download Report
            </button>
          </>
        )}
      </div>
    </Shell>
  );
}
