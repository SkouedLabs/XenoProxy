/** Job API. */

import { api, apiDownload } from '@/lib/api-client';
import type {
  JobDetail,
  JobStats,
  JobStatus,
  JobSummary,
  ObservableType,
  Page,
  PluginReportDetail,
  PluginType,
  ReportStatus,
  Tlp,
  Verdict,
} from '@/lib/types';

export interface GraphNode {
  id: string;
  kind: string;
  label: string;
  data: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  plugin: string | null;
}

export interface RelationGraphData {
  root: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}

export interface RecapVerdictLine {
  job_id: string;
  observable_value: string;
  plugin_name: string;
  plugin_type: PluginType;
  status: ReportStatus;
  verdict: Verdict;
  detection_ratio: string | null;
  headline: string | null;
  links: { label?: string; url?: string }[];
}

export interface Recap {
  subject: {
    job_id: string;
    observable_value: string;
    observable_type: ObservableType;
    status: JobStatus;
    verdict: Verdict;
    tlp: Tlp;
    tags: string[];
    requested_by_name: string;
    created_at: string;
    finished_at: string | null;
    jobs: number;
    reports: number;
  };
  network: {
    ips: string[];
    domains: string[];
    asns: string[];
    countries: string[];
    cities: string[];
    ports: string[];
    technologies: string[];
    cves: string[];
  };
  certificates: {
    names: string[];
    issuers: string[];
    certificates: Record<string, unknown>[];
  };
  registration: { registrars: string[]; contacts: string[]; prefixes: string[] };
  verdicts: RecapVerdictLine[];
  graph: RelationGraphData;
}

export interface JobFilters {
  page: number;
  page_size: number;
  search?: string;
  status?: string;
  verdict?: string;
  observable_type?: string;
  tag?: string;
  requested_by?: string;
  /** Narrow the history to one entry point: 'assistant', 'mcp', 'api', 'ui', 'pivot'. */
  origin?: string;
  /** true shows only jobs a pivot created, false only submitted ones. */
  derived?: boolean;
}

export const jobsApi = {
  list: (filters: JobFilters) => api.get<Page<JobSummary>>('/jobs', { ...filters }),
  get: (jobId: string) => api.get<JobDetail>(`/jobs/${jobId}`),
  children: (jobId: string) => api.get<JobSummary[]>(`/jobs/${jobId}/children`),
  recap: (jobId: string) => api.get<Recap>(`/jobs/${jobId}/recap`),
  report: (jobId: string, pluginName: string) =>
    api.get<PluginReportDetail>(`/jobs/${jobId}/reports/${pluginName}`),
  updateTags: (jobId: string, tags: string[]) =>
    api.patch<JobDetail>(`/jobs/${jobId}/tags`, { tags }),
  rerun: (jobId: string) => api.post<JobDetail>(`/jobs/${jobId}/rerun`),
  /** Stop a running job at its next checkpoint. */
  kill: (jobId: string) => api.post<{ message: string }>(`/jobs/${jobId}/kill`),
  /** Re-run one failed, killed or skipped plugin instead of the whole job. */
  retryReport: (jobId: string, reportId: string) =>
    api.post<JobDetail>(`/jobs/${jobId}/reports/${reportId}/retry`),
  stats: () => api.get<JobStats>('/jobs/stats/overview'),
  download: (jobId: string, format: 'json' | 'markdown') =>
    apiDownload(
      `/jobs/${jobId}/export?format=${format}`,
      `xenoproxy-${jobId}.${format === 'json' ? 'json' : 'md'}`,
    ),
};
