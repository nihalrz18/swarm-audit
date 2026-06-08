const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export interface AuditStartResponse {
  session_id: string;
  status: string;
}

export interface AuditStatus {
  id: string;
  github_url: string;
  status: string;
  total_vulnerabilities: number | null;
  critical_count: number | null;
  high_count: number | null;
  medium_count: number | null;
  low_count: number | null;
  total_risk_usd: string | null;
  repo_name: string | null;
  tech_stack: string[] | null;
  file_count: number | null;
  created_at: string;
  completed_at: string | null;
}

class ApiError extends Error {
  constructor(public readonly statusCode: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      // ignore
    }
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

/**
 * Start a new audit session.
 * @param githubUrl  Public GitHub repository URL.
 */
export async function startAudit(githubUrl: string): Promise<AuditStartResponse> {
  return apiFetch<AuditStartResponse>('/api/audit/start', {
    method: 'POST',
    body: JSON.stringify({ github_url: githubUrl }),
  });
}

/**
 * Poll session status from the database.
 */
export async function getStatus(sessionId: string): Promise<AuditStatus> {
  return apiFetch<AuditStatus>(`/api/audit/${sessionId}/status`);
}

/**
 * Return the PDF download URL for a completed session.
 */
export function getReportUrl(sessionId: string): string {
  return `${API_BASE}/api/report/${sessionId}/download`;
}
