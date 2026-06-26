import { NavLink, Navigate, Route, Routes } from 'react-router-dom';
import type { ReactElement } from 'react';

import { WorkspaceProvider, useWorkspace } from './context/workspace';
import AnalysisPage from './pages/AnalysisPage';
import InvestigationPage from './pages/InvestigationPage';
import MitrePage from './pages/MitrePage';
import ReportPreviewPage from './pages/ReportPreviewPage';
import ThreatIntelPage from './pages/ThreatIntelPage';
import UploadAlertPage from './pages/UploadAlertPage';

const navigation = [
  { to: '/upload', label: 'Upload Alert' },
  { to: '/analysis', label: 'AI Analysis' },
  { to: '/investigation', label: 'Investigation' },
  { to: '/mitre', label: 'MITRE ATT&CK' },
  { to: '/threat-intel', label: 'Threat Intel' },
  { to: '/report', label: 'Report Preview' },
] as const;

function AppShell(): ReactElement {
  const { health } = useWorkspace();

  return (
    <div className="app-shell">
      <div className="app-bg" />
      <aside className="sidebar panel">
        <div className="brand-block">
          <div className="brand-mark">SOC</div>
          <div>
            <p className="eyebrow">AI SOC Assistant</p>
            <h1>Security Operations Console</h1>
          </div>
        </div>
        <p className="sidebar-copy">
          Production-ready portfolio frontend for alert triage, enrichment, and report generation.
        </p>
        <nav className="nav-list">
          {navigation.map((item) => (
            <NavLink key={item.to} to={item.to} className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="status-card">
          <span>Backend Status</span>
          <strong>{health}</strong>
        </div>
      </aside>

      <main className="content-shell">
        <Routes>
          <Route path="/" element={<Navigate to="/upload" replace />} />
          <Route path="/upload" element={<UploadAlertPage />} />
          <Route path="/analysis" element={<AnalysisPage />} />
          <Route path="/investigation" element={<InvestigationPage />} />
          <Route path="/mitre" element={<MitrePage />} />
          <Route path="/threat-intel" element={<ThreatIntelPage />} />
          <Route path="/report" element={<ReportPreviewPage />} />
        </Routes>
      </main>
    </div>
  );
}

export default function App(): ReactElement {
  return (
    <WorkspaceProvider>
      <AppShell />
    </WorkspaceProvider>
  );
}