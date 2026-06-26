import { createContext, useContext, useEffect, useMemo, useState } from 'react';
import type { Dispatch, ReactElement, ReactNode, SetStateAction } from 'react';

import { getHealth } from '../services/api';
import type {
  AbuseIPDBLookupResponse,
  AlertAnalysisResponse,
  IncidentReportResponse,
  MitreMappingResponse,
  SecurityAlertRequest,
  WazuhBatchResponse,
  VirusTotalLookupResponse,
  InvestigationResponse,
} from '../types/api';

export type WorkspaceState = {
  parsedAlert: SecurityAlertRequest | null;
  analysis: AlertAnalysisResponse | null;
  mitre: MitreMappingResponse | null;
  report: IncidentReportResponse | null;
  wazuhBatch: WazuhBatchResponse | null;
  virusTotal: VirusTotalLookupResponse | null;
  abuseIpdb: AbuseIPDBLookupResponse | null;
  investigation: InvestigationResponse | null;
};

type WorkspaceContextValue = {
  state: WorkspaceState;
  setState: Dispatch<SetStateAction<WorkspaceState>>;
  health: string;
};

const initialState: WorkspaceState = {
  parsedAlert: null,
  analysis: null,
  mitre: null,
  report: null,
  wazuhBatch: null,
  virusTotal: null,
  abuseIpdb: null,
  investigation: null,
};

const WorkspaceContext = createContext<WorkspaceContextValue | null>(null);

export function WorkspaceProvider({ children }: { children: ReactNode }): ReactElement {
  const [state, setState] = useState<WorkspaceState>(initialState);
  const [health, setHealth] = useState('checking');

  useEffect(() => {
    let mounted = true;
    void getHealth()
      .then((response) => {
        if (mounted) {
          setHealth(`${response.service} online`);
        }
      })
      .catch(() => {
        if (mounted) {
          setHealth('backend unreachable');
        }
      });

    return () => {
      mounted = false;
    };
  }, []);

  const value = useMemo(
    () => ({ state, setState, health }),
    [health, state],
  );

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>;
}

export function useWorkspace(): WorkspaceContextValue {
  const context = useContext(WorkspaceContext);
  if (!context) {
    throw new Error('useWorkspace must be used inside WorkspaceProvider');
  }
  return context;
}
