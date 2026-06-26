import { useState, useEffect } from 'react';
import type { ReactElement } from 'react';

import Shell from '../components/Shell';
import StatusBlock from '../components/StatusBlock';
import Loader from '../components/Loader';
import { api } from '../services/api';
import { useWorkspace } from '../context/workspace';

// Helper to parse backend error responses
function getErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    try {
      const parsed = JSON.parse(error.message);
      if (parsed && typeof parsed === 'object') {
        if (typeof parsed.detail === 'string') {
          return parsed.detail;
        }
        if (parsed.detail && typeof parsed.detail === 'object') {
          if (parsed.detail.message) {
            return parsed.detail.message;
          }
          if (parsed.detail.error) {
            return `${parsed.detail.error}: ${parsed.detail.message || ''}`;
          }
        }
      }
    } catch {
      // Fallback to raw message
    }
    return error.message;
  }
  return String(error);
}

export default function ThreatIntelPage(): ReactElement {
  const { state, setState } = useWorkspace();
  const [indicator, setIndicator] = useState('8.8.8.8');
  const [query, setQuery] = useState('failed logon');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('Run lookups to enrich the current alert.');
  const [error, setError] = useState<string | null>(null);
  const [searchResult, setSearchResult] = useState<string>('');

  // Status variables mapping to Connected, Not Configured, and Offline
  const [vtConnectionStatus, setVtConnectionStatus] = useState<'checking' | 'connected' | 'not_configured'>('checking');
  const [vtStatusText, setVtStatusText] = useState<string>('Checking...');
  const [esOfflineMessage, setEsOfflineMessage] = useState<string | null>(null);

  // Check VirusTotal config on page load
  useEffect(() => {
    api.lookupVirusTotal({ indicator: '8.8.8.8' })
      .then((res) => {
        if (res.status === 'success') {
          setVtConnectionStatus('connected');
          setVtStatusText('🟢 Connected');
        } else {
          setVtConnectionStatus('not_configured');
          setVtStatusText('🟡 Not Configured');
        }
      })
      .catch(() => {
        setVtConnectionStatus('not_configured');
        setVtStatusText('🟡 Not Configured');
      });
  }, []);

  async function handleLookup(): Promise<void> {
    setLoading(true);
    setError(null);
    setMessage('Querying VirusTotal and AbuseIPDB...');

    let vtResult = null;
    let abuseResult = null;
    const errors: string[] = [];

    // 1. Query VirusTotal
    try {
      vtResult = await api.lookupVirusTotal({ indicator });
      if (vtResult.status === 'success') {
        setVtConnectionStatus('connected');
        setVtStatusText('🟢 Connected');
      } else {
        setVtConnectionStatus('not_configured');
        setVtStatusText('🟡 Not Configured');
        errors.push(`VirusTotal: ${vtResult.message || 'API key not configured'}`);
      }
    } catch (vtError) {
      const msg = getErrorMessage(vtError);
      setVtConnectionStatus('not_configured');
      setVtStatusText('🟡 Not Configured');
      errors.push(`VirusTotal: ${msg}`);
    }

    // 2. Query AbuseIPDB (always returns disabled/offline)
    try {
      abuseResult = await api.lookupAbuseIpdb({ indicator });
    } catch (abuseError) {
      errors.push(`AbuseIPDB: ${getErrorMessage(abuseError)}`);
    }

    // 3. Update workspaces context
    setState((current) => ({ ...current, virusTotal: vtResult, abuseIpdb: abuseResult }));

    if (errors.length > 0) {
      setError(errors.join(' | '));
      setMessage('Lookup completed with configuration constraints.');
    } else {
      setMessage('Threat intelligence data loaded.');
    }
    setLoading(false);
  }

  async function handleSearch(): Promise<void> {
    setLoading(true);
    setError(null);
    setEsOfflineMessage(null);
    setMessage('Searching Elasticsearch...');
    try {
      const [alerts, logs] = await Promise.all([
        api.searchElasticsearchAlerts(query, 5),
        api.searchElasticsearchLogs(query, 5),
      ]);
      setSearchResult(JSON.stringify({ alerts, logs }, null, 2));
      
      if (alerts.status === 'offline' || logs.status === 'offline') {
        setEsOfflineMessage(alerts.message || logs.message || 'Elasticsearch is not configured.');
        setMessage('Elasticsearch is offline.');
      } else {
        setMessage('Elasticsearch search complete.');
      }
    } catch (searchError) {
      setError(searchError instanceof Error ? searchError.message : 'Elasticsearch search failed.');
      setMessage('Search failed.');
    } finally {
      setLoading(false);
    }
  }

  // Calculate total detections for VirusTotal
  const vtTotal = state.virusTotal && state.virusTotal.status === 'success'
    ? (state.virusTotal.malicious || 0) + 
      (state.virusTotal.suspicious || 0) + 
      (state.virusTotal.harmless || 0) + 
      (state.virusTotal.undetected || 0)
    : 0;

  return (
    <Shell title="Threat Intelligence" subtitle="VirusTotal, AbuseIPDB, and Elasticsearch enrichment.">
      <div className="page-grid">
        <section className="panel card-block">
          <div className="panel-header">
            <h3>Indicator Lookup</h3>
            <p>Enter an IP, domain, URL, or hash to query VirusTotal.</p>
          </div>
          
          <div className="status-grid" style={{ marginBottom: '1.5rem' }}>
            <StatusBlock
              title="VirusTotal Status"
              value={vtStatusText}
              tone={vtConnectionStatus === 'connected' ? 'good' : vtConnectionStatus === 'not_configured' ? 'warning' : 'neutral'}
            />
            <StatusBlock
              title="AbuseIPDB Status"
              value="⚫ Offline"
              tone="neutral"
            />
            <StatusBlock
              title="Elasticsearch Status"
              value="⚫ Offline"
              tone="neutral"
            />
          </div>

          <div className="input-grid">
            <label className="field">
              <span>Indicator</span>
              <input value={indicator} onChange={(event) => setIndicator(event.target.value)} />
            </label>
            <button className="primary-button" type="button" onClick={handleLookup} disabled={loading}>
              {loading ? 'Looking up...' : 'Run Threat Intel Lookup'}
            </button>
          </div>
          
          {error ? <div className="error-banner">{error}</div> : null}

          {/* VirusTotal Live Results card */}
          {state.virusTotal && state.virusTotal.status === 'success' && (
            <div className="info-card" style={{ marginTop: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem', padding: '1rem', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '6px' }}>
              <h4 style={{ margin: 0, fontSize: '1.1rem', color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                🛡️ VirusTotal Live Summary
              </h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '0.25rem' }}>
                <div>
                  <span style={{ display: 'block', fontSize: '0.8rem', opacity: 0.8, textTransform: 'uppercase' }}>Detection Ratio</span>
                  <strong style={{ fontSize: '1.15rem' }}>
                    {state.virusTotal.malicious} / {vtTotal}
                  </strong>
                </div>
                <div>
                  <span style={{ display: 'block', fontSize: '0.8rem', opacity: 0.8, textTransform: 'uppercase' }}>Reputation</span>
                  <strong style={{ fontSize: '1.15rem', color: (state.virusTotal.reputation ?? 0) >= 0 ? '#10b981' : '#ef4444' }}>
                    {state.virusTotal.reputation ?? 0}
                  </strong>
                </div>
                <div>
                  <span style={{ display: 'block', fontSize: '0.8rem', opacity: 0.8, textTransform: 'uppercase' }}>Last Analysis</span>
                  <span style={{ fontSize: '0.9rem', fontWeight: 500 }}>
                    {state.virusTotal.last_analysis || 'N/A'}
                  </span>
                </div>
                <div>
                  <span style={{ display: 'block', fontSize: '0.8rem', opacity: 0.8, textTransform: 'uppercase' }}>Community Votes</span>
                  <span style={{ fontSize: '0.9rem', fontWeight: 500 }}>
                    👍 {state.virusTotal.community_votes?.harmless ?? 0} | 👎 {state.virusTotal.community_votes?.malicious ?? 0}
                  </span>
                </div>
              </div>
              {state.virusTotal.permalink && (
                <div style={{ marginTop: '0.5rem' }}>
                  <a href={state.virusTotal.permalink} target="_blank" rel="noopener noreferrer" className="primary-button" style={{ display: 'inline-block', textDecoration: 'none', padding: '6px 12px', fontSize: '0.85rem' }}>
                    View Full VirusTotal Report ↗
                  </a>
                </div>
              )}
            </div>
          )}

          <pre className="code-block" style={{ marginTop: '1rem' }}>
            {state.virusTotal ? JSON.stringify(state.virusTotal, null, 2) : 'VirusTotal JSON result will appear here.'}
          </pre>
          <pre className="code-block">
            {state.abuseIpdb ? JSON.stringify(state.abuseIpdb, null, 2) : 'AbuseIPDB JSON result will appear here.'}
          </pre>
        </section>

        <section className="panel card-block">
          <div className="panel-header">
            <h3>Elasticsearch Search</h3>
            <p>Search index stores (always disabled in this version).</p>
          </div>
          <div className="input-grid">
            <label className="field">
              <span>Query</span>
              <input value={query} onChange={(event) => setQuery(event.target.value)} />
            </label>
            <button className="secondary-button" type="button" onClick={handleSearch} disabled={loading}>
              Search Elasticsearch
            </button>
          </div>
          <Loader label={message} />
          {esOfflineMessage ? (
            <div className="error-banner warning-banner" style={{ backgroundColor: 'rgba(217, 119, 6, 0.1)', borderColor: '#d97706', color: '#d97706', padding: '1rem', borderRadius: '4px', margin: '1rem 0' }}>
              <strong>⚫ Elasticsearch Offline</strong>
              <p style={{ margin: '0.25rem 0 0 0', fontSize: '0.9rem' }}>{esOfflineMessage}</p>
            </div>
          ) : null}
          {error && !esOfflineMessage ? <div className="error-banner">{error}</div> : null}
          <pre className="code-block">{searchResult || 'Search results will appear here.'}</pre>
        </section>
      </div>
    </Shell>
  );
}
