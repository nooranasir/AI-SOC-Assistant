import Shell from '../components/Shell';
import StatusBlock from '../components/StatusBlock';
import Loader from '../components/Loader';
import ErrorBanner from '../components/ErrorBanner';
import { useWorkspace } from '../context/workspace';
import type { ReactElement } from 'react';

export default function AnalysisPage(): ReactElement {
  const { state } = useWorkspace();

  return (
    <Shell title="AI Analysis" subtitle="Structured incident analysis returned by the FastAPI backend.">
      <div className="page-grid two-column">
        <section className="panel card-block">
          <div className="panel-header">
            <h3>Analysis Result</h3>
            <p>Severity, threat explanation, investigation steps, and response guidance.</p>
          </div>
          {!state.analysis ? (
            <div className="empty-state">Run an alert analysis from the Upload Alert page.</div>
          ) : (
            <>
              <div className="status-grid">
                <StatusBlock title="Severity" value={state.analysis.severity} tone={severityTone(state.analysis.severity)} />
                <StatusBlock title="MITRE Technique" value={state.analysis.mitre_technique} />
                <StatusBlock title="MITRE Tactic" value={state.analysis.mitre_tactic} />
              </div>
              <div className="info-card">
                <h4>Alert Summary</h4>
                <p>{state.analysis.alert_summary}</p>
              </div>
              <div className="info-card">
                <h4>Threat Explanation</h4>
                <p>{state.analysis.threat_explanation}</p>
              </div>
              <div className="info-card">
                <h4>Investigation Steps</h4>
                <ul>
                  {state.analysis.investigation_steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
              </div>
              <div className="info-card">
                <h4>Recommended Response</h4>
                <ul>
                  {state.analysis.recommended_response.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
              </div>
              <div className="info-card">
                <h4>Executive Summary</h4>
                <p>{state.analysis.executive_summary}</p>
              </div>
            </>
          )}
        </section>

        <section className="panel card-block">
          <div className="panel-header">
            <h3>Pipeline Status</h3>
            <p>Live progress information from the frontend workflow.</p>
          </div>
          {state.analysis ? <Loader label="Analysis already complete" /> : <ErrorBanner message="Awaiting analysis output." />}
        </section>
      </div>
    </Shell>
  );
}

function severityTone(severity: string): 'neutral' | 'good' | 'warning' | 'critical' {
  const normalized = severity.toLowerCase();
  if (normalized.includes('critical')) {
    return 'critical';
  }
  if (normalized.includes('high')) {
    return 'warning';
  }
  if (normalized.includes('low')) {
    return 'good';
  }
  return 'neutral';
}
