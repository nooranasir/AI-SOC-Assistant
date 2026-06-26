import { useState } from 'react';
import type { ReactElement } from 'react';

import Shell from '../components/Shell';
import { api } from '../services/api';
import { useWorkspace } from '../context/workspace';
import type { SecurityAlertRequest } from '../types/api';

const starterAlert = `{
  "alert_id": "ALERT-2026-0625-001",
  "source": "windows-security",
  "title": "Repeated failed logon attempts",
  "description": "Multiple failed logon attempts were observed against a privileged account from a workstation inside the network.",
  "severity": "medium"
}`;

export default function UploadAlertPage(): ReactElement {
  const { state, setState } = useWorkspace();
  const [alertText, setAlertText] = useState(starterAlert);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationError, setValidationError] = useState<{
    message: string;
    missingFields: string[];
    supportedFormats: string[];
  } | null>(null);
  const [success, setSuccess] = useState<string>('Ready to parse an alert.');

  async function handleUpload(): Promise<void> {
    setLoading(true);
    setError(null);
    setValidationError(null);
    setSuccess('Parsing alert...');

    try {
      const payload = JSON.parse(alertText) as Record<string, unknown>;
      const parsedAlert = await api.parseAlert(payload);
      
      setSuccess('Analyzing alert and extracting MITRE mappings...');
      const analysis = await api.analyzeAlert(parsedAlert);
      const mitre = await api.mapMitre(`${parsedAlert.title} ${parsedAlert.description}`);
      
      setSuccess('Generating playbook investigation steps...');
      const investigation = await api.investigateAlert(parsedAlert);
      
      setSuccess('Building structured incident report...');
      const report = await api.generateIncidentReport({
        alert: parsedAlert,
        analysis,
        timeline: ['Alert submitted from the frontend dashboard.', 'Backend analysis completed.'],
        indicators_of_compromise: collectIndicators(parsedAlert),
      });

      setState((current) => ({
        ...current,
        parsedAlert,
        analysis,
        mitre,
        report,
        investigation,
      }));
      setSuccess('Alert parsed and analyzed successfully.');
    } catch (uploadError) {
      setSuccess('Upload failed.');
      if (uploadError instanceof Error) {
        try {
          const parsed = JSON.parse(uploadError.message);
          // FastAPI HTTPException details are placed under .detail
          if (parsed && parsed.detail && parsed.detail.error === 'Validation Failed') {
            setValidationError({
              message: parsed.detail.message,
              missingFields: parsed.detail.missing_fields || [],
              supportedFormats: parsed.detail.supported_formats || [],
            });
            setError(null);
            return;
          }
          if (parsed && typeof parsed.detail === 'string') {
            setError(parsed.detail);
            return;
          }
        } catch {
          // Message is not a JSON string, fallback to standard error
        }
        setError(uploadError.message);
      } else {
        setError('An unexpected error occurred during processing.');
      }
    } finally {
      setLoading(false);
    }
  }

  function handleLoadSample(): void {
    setAlertText(starterAlert);
    setError(null);
    setValidationError(null);
    setSuccess('Sample alert loaded.');
  }

  return (
    <Shell title="Upload Alert" subtitle="Paste a JSON alert and push it through the backend analysis pipeline.">
      <div className="page-grid">
        <section className="panel card-block">
          <div className="panel-header">
            <h3>Security Alert JSON</h3>
            <p>Use a clean JSON payload matching the existing backend schema.</p>
          </div>
          <textarea
            className="text-area"
            value={alertText}
            onChange={(event) => setAlertText(event.target.value)}
          />
          <div className="button-row">
            <button className="primary-button" type="button" onClick={handleUpload} disabled={loading}>
              {loading ? 'Processing...' : 'Upload and Analyze'}
            </button>
            <button className="secondary-button" type="button" onClick={handleLoadSample} disabled={loading}>
              Load Sample
            </button>
          </div>
          <p className="status-line">{success}</p>
          
          {validationError ? (
            <div className="error-banner validation-error-panel" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', padding: '1rem', borderRadius: '4px', marginTop: '1rem' }}>
              <strong style={{ fontSize: '1.05rem', color: '#dc2626' }}>⚠️ Alert Validation Failed</strong>
              <p style={{ margin: 0, fontSize: '0.95rem' }}>{validationError.message}</p>
              {validationError.missingFields.length > 0 && (
                <div style={{ marginTop: '0.25rem', fontSize: '0.9rem' }}>
                  <span style={{ fontWeight: 'bold' }}>Missing Fields: </span>
                  {validationError.missingFields.map((field) => (
                    <code key={field} style={{ backgroundColor: 'rgba(220, 38, 38, 0.1)', color: '#dc2626', padding: '2px 6px', borderRadius: '4px', margin: '0 4px', border: '1px solid rgba(220, 38, 38, 0.2)', fontFamily: 'monospace' }}>
                      {field}
                    </code>
                  ))}
                </div>
              )}
              {validationError.supportedFormats.length > 0 && (
                <div style={{ marginTop: '0.5rem', fontSize: '0.9rem', opacity: 0.9 }}>
                  <span style={{ fontWeight: 'bold' }}>Supported formats: </span>
                  <ul style={{ margin: '0.25rem 0 0 1.2rem', padding: 0 }}>
                    {validationError.supportedFormats.map((format) => (
                      <li key={format} style={{ listStyleType: 'disc' }}>{format}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : null}
          
          {error ? <div className="error-banner">{error}</div> : null}
        </section>

        <section className="panel summary-block">
          <div className="panel-header">
            <h3>Current Payload</h3>
            <p>Parsed alert and report metadata will appear here after upload.</p>
          </div>
          <pre className="code-block">{state.parsedAlert ? JSON.stringify(state.parsedAlert, null, 2) : 'No alert parsed yet.'}</pre>
        </section>
      </div>
    </Shell>
  );
}

function collectIndicators(alert: SecurityAlertRequest): string[] {
  return [alert.alert_id, alert.source, alert.title].filter((item): item is string => Boolean(item));
}
