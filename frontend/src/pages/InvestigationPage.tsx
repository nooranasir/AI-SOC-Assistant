import { useState } from 'react';
import type { ReactElement } from 'react';

import Shell from '../components/Shell';
import StatusBlock from '../components/StatusBlock';
import { useWorkspace } from '../context/workspace';
import type { ExtractedIOC } from '../types/api';

type PlaybookTab = 'investigation' | 'containment' | 'recovery' | 'detection';

export default function InvestigationPage(): ReactElement {
  const { state } = useWorkspace();
  const [activeTab, setActiveTab] = useState<PlaybookTab>('investigation');

  const { investigation } = state;

  function getConfidenceTone(score: number): 'neutral' | 'good' | 'warning' | 'critical' {
    if (score >= 80) return 'critical';
    if (score >= 50) return 'warning';
    if (score >= 20) return 'neutral';
    return 'good';
  }

  function getIocReputationBadge(ioc: ExtractedIOC): ReactElement {
    if (ioc.indicator_type === 'username') {
      return <span className="badge tone-neutral">User Account</span>;
    }

    const vtMalicious = ioc.virustotal?.malicious ?? 0;
    const vtSuspicious = ioc.virustotal?.suspicious ?? 0;
    const abuseScore = ioc.abuseipdb?.confidence_score ?? 0;

    const isHighRisk = vtMalicious > 0 || abuseScore >= 50;
    const isMediumRisk = vtSuspicious > 0 || (abuseScore > 0 && abuseScore < 50);

    if (isHighRisk) {
      return (
        <span className="badge tone-critical">
          Malicious ({vtMalicious > 0 ? `VT: ${vtMalicious}` : ''}
          {abuseScore >= 50 ? ` Abuse: ${abuseScore}%` : ''})
        </span>
      );
    }

    if (isMediumRisk) {
      return (
        <span className="badge tone-warning">
          Suspicious ({vtSuspicious > 0 ? `VT: ${vtSuspicious}` : ''}
          {abuseScore > 0 ? ` Abuse: ${abuseScore}%` : ''})
        </span>
      );
    }

    if (ioc.virustotal || ioc.abuseipdb) {
      return <span className="badge tone-good">Clean / Low Risk</span>;
    }

    return <span className="badge tone-neutral">No Reputation Data</span>;
  }

  return (
    <Shell title="Investigation Assistant" subtitle="Enriched threat intelligence and automated SOC playbooks.">
      {!investigation ? (
        <div className="empty-state card-block panel">
          <h3>No Active Investigation</h3>
          <p>Please upload and analyze a security alert to populate the investigation playbook.</p>
        </div>
      ) : (
        <div className="page-grid">
          {/* Summary Panel */}
          <section className="panel card-block" style={{ gridColumn: 'span 12' }}>
            <div className="panel-header">
              <h3>Investigation Summary</h3>
              <p>Key findings and overall confidence score calculated from alert content and indicators.</p>
            </div>
            <div className="status-grid" style={{ marginBottom: '1.5rem' }}>
              <StatusBlock
                title="Confidence Score"
                value={`${investigation.confidence_score}%`}
                tone={getConfidenceTone(investigation.confidence_score)}
              />
              <StatusBlock
                title="Total Extracted IOCs"
                value={investigation.iocs.length.toString()}
              />
              <StatusBlock
                title="Status"
                value={investigation.confidence_score >= 50 ? 'Threat Verified' : 'Suspicious / Unverified'}
                tone={investigation.confidence_score >= 50 ? 'critical' : 'warning'}
              />
            </div>
            <div className="info-card">
              <p style={{ lineHeight: '1.6', fontSize: '1.05rem' }}>{investigation.summary}</p>
            </div>
          </section>

          {/* IOCs Panel */}
          <section className="panel card-block" style={{ gridColumn: 'span 12' }}>
            <div className="panel-header">
              <h3>Extracted Indicators of Compromise (IOCs)</h3>
              <p>IPs, domains, URLs, hashes, and usernames analyzed by VirusTotal and AbuseIPDB.</p>
            </div>
            {investigation.iocs.length === 0 ? (
              <p className="status-line">No indicators were extracted from this alert.</p>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table className="data-table" style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid var(--border-color)', paddingBottom: '10px' }}>
                      <th style={{ padding: '12px 8px' }}>Indicator</th>
                      <th style={{ padding: '12px 8px' }}>Type</th>
                      <th style={{ padding: '12px 8px' }}>Reputation / Status</th>
                      <th style={{ padding: '12px 8px' }}>Details / Source</th>
                    </tr>
                  </thead>
                  <tbody>
                    {investigation.iocs.map((ioc, index) => (
                      <tr key={index} style={{ borderBottom: '1px solid var(--border-color)' }}>
                        <td style={{ padding: '12px 8px', fontWeight: '500', fontFamily: ioc.indicator_type !== 'username' ? 'monospace' : 'inherit' }}>
                          {ioc.indicator}
                        </td>
                        <td style={{ padding: '12px 8px' }}>
                          <span style={{ textTransform: 'capitalize', fontSize: '0.85rem' }}>
                            {ioc.indicator_type.replace('_', ' ')}
                          </span>
                        </td>
                        <td style={{ padding: '12px 8px' }}>{getIocReputationBadge(ioc)}</td>
                        <td style={{ padding: '12px 8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
                          {ioc.virustotal?.permalink ? (
                            <a
                              href={ioc.virustotal.permalink}
                              target="_blank"
                              rel="noreferrer"
                              className="accent-link"
                              style={{ marginRight: '10px' }}
                            >
                              VirusTotal Link
                            </a>
                          ) : null}
                          {ioc.abuseipdb?.isp ? (
                            <span>ISP: {ioc.abuseipdb.isp} ({ioc.abuseipdb.country_code})</span>
                          ) : ioc.virustotal ? (
                            <span>Reputation score: {ioc.virustotal.reputation ?? 'N/A'}</span>
                          ) : (
                            <span>Static extraction</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          {/* SOC Playbook Panel */}
          <section className="panel card-block" style={{ gridColumn: 'span 12' }}>
            <div className="panel-header">
              <h3>SOC Investigation Playbook</h3>
              <p>Step-by-step containment, recovery, and detection recommendations.</p>
            </div>
            
            {/* Custom Tab Row */}
            <div className="button-row" style={{ borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem', marginBottom: '1.5rem', gap: '0.5rem' }}>
              <button
                className={`secondary-button ${activeTab === 'investigation' ? 'primary-button' : ''}`}
                style={{ padding: '8px 16px', borderRadius: '4px', fontSize: '0.9rem' }}
                onClick={() => setActiveTab('investigation')}
              >
                1. Investigation Steps
              </button>
              <button
                className={`secondary-button ${activeTab === 'containment' ? 'primary-button' : ''}`}
                style={{ padding: '8px 16px', borderRadius: '4px', fontSize: '0.9rem' }}
                onClick={() => setActiveTab('containment')}
              >
                2. Containment Actions
              </button>
              <button
                className={`secondary-button ${activeTab === 'recovery' ? 'primary-button' : ''}`}
                style={{ padding: '8px 16px', borderRadius: '4px', fontSize: '0.9rem' }}
                onClick={() => setActiveTab('recovery')}
              >
                3. Recovery Tasks
              </button>
              <button
                className={`secondary-button ${activeTab === 'detection' ? 'primary-button' : ''}`}
                style={{ padding: '8px 16px', borderRadius: '4px', fontSize: '0.9rem' }}
                onClick={() => setActiveTab('detection')}
              >
                4. Detection Rules
              </button>
            </div>

            <div className="info-card">
              {activeTab === 'investigation' && (
                <>
                  <h4 style={{ marginBottom: '1rem', color: 'var(--text-color)' }}>Recommended Forensic Investigation</h4>
                  <ul>
                    {investigation.recommended_investigation_steps.map((step, idx) => (
                      <li key={idx} style={{ marginBottom: '0.5rem', lineHeight: '1.5' }}>{step}</li>
                    ))}
                  </ul>
                </>
              )}

              {activeTab === 'containment' && (
                <>
                  <h4 style={{ marginBottom: '1rem', color: 'var(--accent-red)' }}>Immediate Containment Steps</h4>
                  <ul>
                    {investigation.containment_actions.map((action, idx) => (
                      <li key={idx} style={{ marginBottom: '0.5rem', lineHeight: '1.5' }}>{action}</li>
                    ))}
                  </ul>
                </>
              )}

              {activeTab === 'recovery' && (
                <>
                  <h4 style={{ marginBottom: '1rem', color: 'var(--accent-green)' }}>Recovery & Remediation</h4>
                  <ul>
                    {investigation.recovery_actions.map((action, idx) => (
                      <li key={idx} style={{ marginBottom: '0.5rem', lineHeight: '1.5' }}>{action}</li>
                    ))}
                  </ul>
                </>
              )}

              {activeTab === 'detection' && (
                <>
                  <h4 style={{ marginBottom: '1rem', color: 'var(--text-color)' }}>Future Detection Recommendations</h4>
                  <ul>
                    {investigation.detection_recommendations.map((rec, idx) => (
                      <li key={idx} style={{ marginBottom: '0.5rem', lineHeight: '1.5' }}>{rec}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          </section>
        </div>
      )}
    </Shell>
  );
}
