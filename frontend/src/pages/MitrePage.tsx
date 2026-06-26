import Shell from '../components/Shell';
import { useWorkspace } from '../context/workspace';
import type { ReactElement } from 'react';

export default function MitrePage(): ReactElement {
  const { state } = useWorkspace();

  return (
    <Shell title="MITRE ATT&CK Mapping" subtitle="View the mapped technique and supporting context.">
      <div className="panel card-block">
        {!state.mitre ? (
          <div className="empty-state">Trigger alert analysis to populate the MITRE map.</div>
        ) : (
          <div className="mitre-layout">
            <div className="info-card">
              <h4>Technique ID</h4>
              <p>{state.mitre.technique_id ?? 'Unmapped'}</p>
            </div>
            <div className="info-card">
              <h4>Technique Name</h4>
              <p>{state.mitre.technique_name ?? 'Unmapped'}</p>
            </div>
            <div className="info-card">
              <h4>Tactic</h4>
              <p>{state.mitre.tactic ?? 'Unmapped'}</p>
            </div>
            <div className="info-card wide">
              <h4>Description</h4>
              <p>{state.mitre.description ?? 'No description available.'}</p>
            </div>
            <div className="info-card wide">
              <h4>Matched Keywords</h4>
              <p>{state.mitre.matched_keywords.join(', ') || 'No keyword match'}</p>
            </div>
          </div>
        )}
      </div>
    </Shell>
  );
}
