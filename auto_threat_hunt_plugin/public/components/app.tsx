import React, { useEffect, useMemo, useState } from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import ReactFlow, { Background, Controls } from 'reactflow';
import 'reactflow/dist/style.css';

import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCard,
  EuiFlexGrid,
  EuiFlexGroup,
  EuiFlexItem,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiFieldText,
  EuiFieldNumber,
  EuiFormRow,
  EuiSelect,
  EuiRadioGroup,
  EuiHealth,
  EuiHorizontalRule,
  EuiPage,
  EuiPageBody,
  EuiPageHeader,
  EuiPanel,
  EuiSpacer,
  EuiStat,
  EuiTabbedContent,
  EuiText,
  EuiTitle,
} from '@elastic/eui';

import { CoreStart } from '../../../../core/public';
import { NavigationPublicPluginStart } from '../../../navigation/public';
import { PLUGIN_ID } from '../../common';
import { CampaignDetails } from './CampaignDetails';
import { CampaignInvestigationFlyout } from './CampaignInvestigationFlyout';

interface AutoThreatHuntAppDeps {
  basename: string;
  notifications: CoreStart['notifications'];
  http: CoreStart['http'];
  navigation: NavigationPublicPluginStart;
}

const riskColor = (risk: number) => {
  if (risk >= 80) return 'danger';
  if (risk >= 60) return 'warning';
  if (risk >= 40) return 'primary';
  return 'success';
};

const arr = (v: any) => Array.isArray(v) ? v : v ? [v] : [];

const formatTime = (ts: string) => {
  if (!ts || ts === '-') return '-';
  try {
    return new Date(ts).toLocaleString('vi-VN', {
      timeZone: 'Asia/Ho_Chi_Minh',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch (e) {
    return ts;
  }
};

const pageNumbers = (totalPages: number) => {
  return Array.from({ length: totalPages }, (_, i) => i);
};

const paginate = (items: any[] = [], page: number, pageSize: number) => {
  const start = page * pageSize;
  return items.slice(start, start + pageSize);
};

const pageCount = (items: any[] = [], pageSize: number) => {
  return Math.max(1, Math.ceil(items.length / pageSize));
};

const formatSize = (size: number) => {
  if (!size && size !== 0) return '-';
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
};

const countTechniqueEvents = (events: any[], techniqueId: string) => {
  return events.filter((e) => arr(e.mitre_id).includes(techniqueId)).length;
};

const evidenceForTechnique = (events: any[], techniqueId: string) => {
  return events
    .filter((e) => arr(e.mitre_id).includes(techniqueId))
    .slice(0, 5)
    .map((e) => ({
      time: e.timestamp,
      rule: e.rule_id,
      level: e.level,
      srcip: e.srcip,
      url: e.url,
      description: e.description,
    }));
};

const getCampaignIocs = (campaign: any) => {
  const events = campaign?.events || [];
  const ips = new Set<string>();
  const urls = new Set<string>();
  const files = new Set<string>();
  const users = new Set<string>();
  const hosts = new Set<string>();

  for (const e of events) {
    if (e.srcip && e.srcip !== '-') ips.add(e.srcip);
    if (e.url && e.url !== '-') urls.add(e.url);
    if (e.agent && e.agent !== '-') hosts.add(e.agent);

    const log = String(e.full_log || '');
    if (log.includes('/var/www/html/shell.php') || log.includes('shell.php')) {
      files.add('/var/www/html/shell.php');
    }
    if (log.includes('root')) users.add('root');
  }

  return {
    ips: Array.from(ips),
    urls: Array.from(urls).slice(0, 30),
    files: Array.from(files),
    users: Array.from(users),
    hosts: Array.from(hosts),
  };
};

export const AutoThreatHuntApp = ({ basename, navigation, http }: AutoThreatHuntAppDeps) => {
  const [data, setData] = useState<any>(null);
  const [selectedCampaign, setSelectedCampaign] = useState<any>(null);
  const [drawerCampaign, setDrawerCampaign] = useState<any>(null);
  const [isCampaignFlyoutOpen, setCampaignFlyoutOpen] = useState(false); // ← MỚI
  const [pivot, setPivot] = useState<string>('');
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [reports, setReports] = useState<any[]>([]);
  const [huntName, setHuntName] = useState('Threat Hunt');
  const [reportFormat, setReportFormat] = useState<'md' | 'pdf'>('md');
  const [timeFrom, setTimeFrom] = useState('now-120d');
  const [minLevel, setMinLevel] = useState(12);
  const [seedSize, setSeedSize] = useState(30);
  const [pivotMinutes, setPivotMinutes] = useState(30);
  const [reportView, setReportView] = useState<any>(null);
  const [reportTitle, setReportTitle] = useState('');
  const [reportType, setReportType] = useState<'md' | 'pdf'>('md');
  const [showReport, setShowReport] = useState(false);
  const [reportCampaignPage, setReportCampaignPage] = useState(0);
  const [reportChainPage, setReportChainPage] = useState(0);
  const [reportRecommendationPage, setReportRecommendationPage] = useState(0);
  const [timelinePage, setTimelinePage] = useState(0);
  const [timelinePageSize, setTimelinePageSize] = useState(20);

  const loadReports = async () => {
    try {
      const rep = await http.get('/api/auto_threat_hunt/reports');
      setReports(rep || []);
    } catch (e) {
      setReports([]);
    }
  };

  const load = async () => {
    setError('');
    try {
      const json = await http.get('/api/auto_threat_hunt/latest');
      setData(json);
      setSelectedCampaign(json.campaigns?.[0] || null);

      if (json.hunt_params?.time_from) setTimeFrom(json.hunt_params.time_from);
      if (json.hunt_params?.min_level) setMinLevel(json.hunt_params.min_level);
      if (json.hunt_params?.seed_size) setSeedSize(json.hunt_params.seed_size);
      if (json.hunt_params?.pivot_minutes) setPivotMinutes(json.hunt_params.pivot_minutes);
    } catch (e) {
      setError(String(e));
    }
  };

  const runHuntNow = async () => {
    setRunning(true);
    try {
      await http.post('/api/auto_threat_hunt/run', {
        body: {
          hunt_name: huntName,
          format: reportFormat,
          time_from: timeFrom,
          time_to: 'now',
          min_level: minLevel,
          seed_size: seedSize,
          pivot_minutes: pivotMinutes,
        },
      });
      await load();
      await loadReports();
    } finally {
      setRunning(false);
    }
  };

  const openReport = async (filename: string) => {
    const r = await http.get('/api/auto_threat_hunt/report', {
      query: { filename },
    });
    setReportTitle(r.filename);
    setReportType(r.type || 'md');
    setReportView(r.view || null);
    setReportCampaignPage(0);
    setReportChainPage(0);
    setReportRecommendationPage(0);
    setShowReport(true);
  };

  const generateExecutiveReport = async () => {
    setRunning(true);
    try {
      await http.post('/api/auto_threat_hunt/report/executive');
      await loadReports();
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    load();
    loadReports();
  }, []);

  const baseEvents = selectedCampaign?.events || data?.timeline || [];

  useEffect(() => {
    setTimelinePage(0);
  }, [pivot, selectedCampaign]);

  const filteredEvents = useMemo(() => {
    if (!pivot) return baseEvents;
    return baseEvents.filter((e: any) => {
      const text = [
        e.timestamp,
        e.agent,
        e.rule_id,
        e.level,
        e.description,
        arr(e.mitre_id).join(','),
        e.srcip,
        e.url,
        e.full_log,
      ].join(' ').toLowerCase();
      return text.includes(pivot.toLowerCase());
    });
  }, [baseEvents, pivot]);

  const chain = selectedCampaign?.chain || data?.attack_chain || [];

  const flow = useMemo(() => {
    const nodes = chain.map((x: any, idx: number) => {
      const eventCount = countTechniqueEvents(baseEvents, x.technique_id);
      return {
        id: x.technique_id,
        position: { x: idx * 230, y: 80 },
        data: {
          label: `${x.technique_id}\n${x.name}\n(${eventCount} events)`,
        },
        style: {
          width: 190,
          border: '1px solid #006bb4',
          borderRadius: 8,
          padding: 8,
          fontSize: 11,
          background: eventCount > 0 ? '#e8f3ff' : '#ffffff',
        },
      };
    });

    const graphEdges = selectedCampaign?.edges || data?.attack_edges || [];
    const edges = graphEdges.map((e: any, idx: number) => ({
      id: `e-${idx}`,
      source: e.source,
      target: e.target,
      animated: true,
      label: e.weight ? `weight ${e.weight}` : 'related',
    }));

    return { nodes, edges };
  }, [chain, baseEvents]);

  if (error) {
    return (
      <Router basename={basename}>
        <navigation.ui.TopNavMenu appName={PLUGIN_ID} showSearchBar={false} useDefaultBehaviors={true} />
        <EuiPage><EuiPageBody>
          <EuiCallOut color="danger" title="Failed to load hunt data">{error}</EuiCallOut>
        </EuiPageBody></EuiPage>
      </Router>
    );
  }

  if (!data) {
    return (
      <Router basename={basename}>
        <navigation.ui.TopNavMenu appName={PLUGIN_ID} showSearchBar={false} useDefaultBehaviors={true} />
        <EuiPage><EuiPageBody>
          <EuiText>Loading Auto Threat Hunt data...</EuiText>
        </EuiPageBody></EuiPage>
      </Router>
    );
  }

  const overview = data.overview || {};
  const campaigns = data.campaigns || [];
  const iocs = data.iocs || {};
  const campaignIocs = getCampaignIocs(selectedCampaign);

  const recommendationsForSelected = (data.recommendations || []).filter((r: any) =>
    chain.some((c: any) => c.technique_id === r.technique_id)
  );

  const campaignColumns: any = [
    {
      field: 'risk_score',
      name: 'Risk',
      render: (risk: number) => <EuiBadge color={riskColor(risk)}>{risk}</EuiBadge>,
      sortable: true,
    },
    { field: 'agent', name: 'Agent' },
    { field: 'srcip', name: 'Src IP' },
    { field: 'event_count', name: 'Events', sortable: true },
    { field: 'techniques', name: 'Techniques', sortable: true },
    {
      field: 'confidence',
      name: 'Confidence',
      render: (v: number) => `${v}%`,
      sortable: true,
    },
    {
      name: 'Action',
      render: (item: any) => (
        <EuiButton
          size="s"
          onClick={() => {
            setSelectedCampaign(item);
            setDrawerCampaign(item);
            setPivot('');
          }}
        >
          View Details
        </EuiButton>
      ),
    },
  ];

  const timelineColumns: any = [
    {
      field: 'timestamp',
      name: 'Time',
      render: (v: string) => formatTime(v),
    },
    { field: 'agent', name: 'Agent' },
    {
      field: 'source',
      name: 'Source',
      render: (v: string) => <EuiBadge color={v === 'archive' ? 'primary' : 'success'}>{v}</EuiBadge>,
    },
    { field: 'rule_id', name: 'Rule' },
    {
      field: 'level',
      name: 'Level',
      render: (v: number) => <EuiBadge color={v >= 12 ? 'danger' : v >= 8 ? 'warning' : 'hollow'}>{v}</EuiBadge>,
    },
    {
      field: 'mitre_id',
      name: 'MITRE',
      render: (v: any) => arr(v).join(', '),
    },
    { field: 'description', name: 'Description' },
  ];

  const reportDownloadUrl = (filename: string) =>
    http.basePath.prepend(`/api/auto_threat_hunt/report/download?filename=${encodeURIComponent(filename)}`);

  const reportColumns: any = [
    { field: 'filename', name: 'Filename' },
    { field: 'type', name: 'Type', render: (v: string) => <EuiBadge>{v}</EuiBadge> },
    { field: 'extension', name: 'Format', render: (v: string) => <EuiBadge>{String(v).toUpperCase()}</EuiBadge> },
    { field: 'size', name: 'Size', render: (v: number) => formatSize(v) },
    {
      field: 'modified',
      name: 'Modified',
      render: (v: number) => formatTime(new Date(v * 1000).toISOString()),
    },
    {
      name: 'Action',
      render: (item: any) => (
        <EuiFlexGroup gutterSize="s">
          <EuiFlexItem grow={false}>
            <EuiButton size="s" onClick={() => openReport(item.filename)}>View</EuiButton>
          </EuiFlexItem>
          <EuiFlexItem grow={false}>
            <EuiButtonEmpty size="s" href={reportDownloadUrl(item.filename)}>Download</EuiButtonEmpty>
          </EuiFlexItem>
        </EuiFlexGroup>
      ),
    },
  ];

  const makeIocTab = (name: string, values: string[]) => ({
    id: name,
    name: name.toUpperCase(),
    content: (
      <EuiPanel color="subdued">
        {(values || []).filter((x) => x && x !== '-').slice(0, 100).map((x: string) => (
          <EuiButtonEmpty key={x} size="xs" onClick={() => setPivot(x)}>{x}</EuiButtonEmpty>
        ))}
      </EuiPanel>
    ),
  });

  const iocTabs = [
    makeIocTab('ips', iocs.ips || []),
    makeIocTab('urls', iocs.urls || []),
    makeIocTab('files', iocs.files || []),
    makeIocTab('users', iocs.users || []),
    makeIocTab('hosts', iocs.hosts || []),
  ];

  return (
    <Router basename={basename}>
      <>
        <navigation.ui.TopNavMenu appName={PLUGIN_ID} showSearchBar={false} useDefaultBehaviors={true} />

        <EuiPage restrictWidth="1400px">
          <EuiPageBody component="main">
            <EuiPageHeader>
              <EuiTitle size="l"><h1>Auto Threat Hunt</h1></EuiTitle>
            </EuiPageHeader>

            <EuiCallOut
              title="MITRE ATT&CK-based Automated Threat Hunting for Wazuh XDR"
              color="primary"
              iconType="iInCircle"
            >
              <p>Latest result: {formatTime(data.generated_at)}</p>
              <p>Valid Wazuh agents: {(data.valid_agents || []).join(', ')}</p>
            </EuiCallOut>

            <EuiSpacer size="m" />

            <EuiPanel>
              <EuiTitle size="s"><h3>Run New Hunt</h3></EuiTitle>
              <EuiSpacer size="s" />
              <EuiFlexGroup alignItems="center">
                <EuiFlexItem>
                  <EuiFormRow label="Hunt name">
                    <EuiFieldText
                      value={huntName}
                      onChange={(e) => setHuntName(e.target.value)}
                      placeholder="Web Attack Investigation"
                      aria-label="Hunt name"
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiFormRow label="Time range">
                    <EuiSelect
                      value={timeFrom}
                      onChange={(e) => setTimeFrom(e.target.value)}
                      options={[
                        { value: 'now-1h', text: 'Last 1 hour' },
                        { value: 'now-24h', text: 'Last 24 hours' },
                        { value: 'now-7d', text: 'Last 7 days' },
                        { value: 'now-30d', text: 'Last 30 days' },
                        { value: 'now-120d', text: 'Last 120 days' },
                      ]}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiFormRow label="Min level">
                    <EuiFieldNumber
                      value={minLevel}
                      min={0}
                      max={15}
                      onChange={(e) => setMinLevel(Number(e.target.value))}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiFormRow label="Seeds">
                    <EuiFieldNumber
                      value={seedSize}
                      min={1}
                      max={200}
                      onChange={(e) => setSeedSize(Number(e.target.value))}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiFormRow label="Pivot minutes">
                    <EuiFieldNumber
                      value={pivotMinutes}
                      min={5}
                      max={240}
                      onChange={(e) => setPivotMinutes(Number(e.target.value))}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiFormRow label="Format">
                    <EuiRadioGroup
                      options={[
                        { id: 'md', label: 'Markdown' },
                        { id: 'pdf', label: 'PDF' },
                      ]}
                      idSelected={reportFormat}
                      onChange={(id) => setReportFormat(id as 'md' | 'pdf')}
                    />
                  </EuiFormRow>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiPanel>

            <EuiSpacer size="m" />

            <EuiFlexGroup>
              <EuiFlexItem grow={false}>
                <EuiButton fill isLoading={running} onClick={runHuntNow}>Run Hunt Now</EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButton isLoading={running} onClick={generateExecutiveReport}>Generate Executive Report</EuiButton>
              </EuiFlexItem>
              <EuiFlexItem grow={false}>
                <EuiButtonEmpty onClick={loadReports}>Refresh Reports</EuiButtonEmpty>
              </EuiFlexItem>
            </EuiFlexGroup>

            <EuiSpacer size="l" />

            <EuiFlexGrid columns={4}>
              <EuiCard title={<EuiStat title={overview.total_events} description="Total Events" />} description="" />
              <EuiCard title={<EuiStat title={overview.alert_events || 0} description="Alert Events" />} description="" />
              <EuiCard title={<EuiStat title={overview.archive_events || 0} description="Archive Events" />} description="" />
              <EuiCard title={<EuiStat title={overview.seeds} description="Seeds" />} description="" />
              <EuiCard title={<EuiStat title={overview.campaigns} description="Campaigns" />} description="" />
              <EuiCard title={<EuiStat title={overview.high_risk} description="High Risk" />} description="" />
              <EuiCard title={<EuiStat title={overview.mitre_techniques} description="MITRE Techniques" />} description="" />
            </EuiFlexGrid>

            <EuiSpacer size="l" />

            <EuiFlexGroup>
              <EuiFlexItem grow={2}>
                <EuiPanel>
                  <EuiTitle size="m"><h2>Campaigns</h2></EuiTitle>
                  <EuiSpacer />
                  <EuiBasicTable items={campaigns} columns={campaignColumns} pagination={{ pageSize: 10 }} />
                </EuiPanel>
              </EuiFlexItem>

              {/* ↓ PANEL SELECTED CAMPAIGN ĐÃ SỬA */}
              <EuiFlexItem grow={1}>
                <EuiPanel>
                  <EuiTitle size="m"><h2>Selected Campaign</h2></EuiTitle>
                  <EuiSpacer />
                  {!selectedCampaign ? (
                    <EuiText>No campaign selected.</EuiText>
                  ) : (
                    <>
                      <EuiText>
                        <p><b>Agent:</b> {selectedCampaign.agent || '-'}</p>
                        <p><b>Src IP:</b> {selectedCampaign.srcip || '-'}</p>
                        <p><b>Risk:</b> <EuiBadge color={riskColor(selectedCampaign.risk_score)}>{selectedCampaign.risk_score}</EuiBadge></p>
                        <p><b>Events:</b> {selectedCampaign.event_count}</p>
                        <p><b>Confidence:</b> {selectedCampaign.confidence}%</p>
                      </EuiText>
                      <EuiSpacer />
                      <EuiButton fill onClick={() => setCampaignFlyoutOpen(true)}>
                        Open Investigation
                      </EuiButton>
                    </>
                  )}
                </EuiPanel>
              </EuiFlexItem>
            </EuiFlexGroup>

            <EuiSpacer size="l" />

            <EuiPanel>
              <EuiTitle size="m"><h2>ATT&CK Chain Graph with Evidence Count</h2></EuiTitle>
              <EuiSpacer />
              <div style={{ height: 380 }}>
                <ReactFlow nodes={flow.nodes} edges={flow.edges} fitView>
                  <Background />
                  <Controls />
                </ReactFlow>
              </div>
            </EuiPanel>

            <EuiSpacer size="l" />

            <EuiPanel>
              <EuiTitle size="m"><h2>IOC Browser</h2></EuiTitle>
              <EuiSpacer />
              <EuiTabbedContent tabs={iocTabs} initialSelectedTab={iocTabs[0]} />
            </EuiPanel>

            <EuiSpacer size="l" />

            <EuiPanel>
              <EuiFlexGroup justifyContent="spaceBetween" alignItems="center">
                <EuiFlexItem grow={false}>
                  <EuiTitle size="m"><h2>Timeline</h2></EuiTitle>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  {pivot ? (
                    <EuiButtonEmpty size="s" onClick={() => setPivot('')}>
                      Clear pivot: {pivot}
                    </EuiButtonEmpty>
                  ) : null}
                </EuiFlexItem>
              </EuiFlexGroup>

              <EuiSpacer />
              <EuiBasicTable
                items={paginate(filteredEvents, timelinePage, timelinePageSize)}
                columns={timelineColumns}
              />

              <EuiSpacer size="s" />

              <EuiFlexGroup justifyContent="spaceBetween" alignItems="center">
                <EuiFlexItem grow={false}>
                  <EuiText size="s">
                    Showing {filteredEvents.length === 0 ? 0 : timelinePage * timelinePageSize + 1}
                    -{Math.min((timelinePage + 1) * timelinePageSize, filteredEvents.length)}
                    / {filteredEvents.length} events
                  </EuiText>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiFlexGroup gutterSize="xs" wrap>
                    <EuiFlexItem grow={false}>
                      <EuiButtonEmpty
                        size="xs"
                        disabled={timelinePage === 0}
                        onClick={() => setTimelinePage(Math.max(0, timelinePage - 1))}
                      >
                        Previous
                      </EuiButtonEmpty>
                    </EuiFlexItem>
                    {pageNumbers(pageCount(filteredEvents, timelinePageSize)).slice(0, 20).map((page: number) => (
                      <EuiFlexItem grow={false} key={page}>
                        <EuiButtonEmpty
                          size="xs"
                          isSelected={page === timelinePage}
                          onClick={() => setTimelinePage(page)}
                        >
                          {page + 1}
                        </EuiButtonEmpty>
                      </EuiFlexItem>
                    ))}
                    <EuiFlexItem grow={false}>
                      <EuiButtonEmpty
                        size="xs"
                        disabled={timelinePage + 1 >= pageCount(filteredEvents, timelinePageSize)}
                        onClick={() => setTimelinePage(timelinePage + 1)}
                      >
                        Next
                      </EuiButtonEmpty>
                    </EuiFlexItem>
                  </EuiFlexGroup>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiPanel>

            <EuiSpacer size="l" />

            <EuiPanel>
              <EuiTitle size="m"><h2>Report History</h2></EuiTitle>
              <EuiSpacer />
              <EuiBasicTable items={reports} columns={reportColumns} pagination={{ pageSize: 10 }} />
            </EuiPanel>

            <EuiHorizontalRule />

            <EuiText size="s">
              <EuiHealth color="success">Engine connected to Wazuh/OpenSearch/MITRE CTI</EuiHealth>
            </EuiText>
          </EuiPageBody>
        </EuiPage>

        {/* ↓ CAMPAIGN INVESTIGATION FLYOUT MỚI */}
        {isCampaignFlyoutOpen && selectedCampaign && (
          <CampaignInvestigationFlyout
            campaign={selectedCampaign}
            onClose={() => setCampaignFlyoutOpen(false)}
          />
        )}

        {showReport && (
          <EuiFlyout onClose={() => setShowReport(false)} size="l">
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m"><h2>{reportTitle}</h2></EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              {reportView ? (
                <>
                  <EuiPanel>
                    <EuiTitle size="s"><h3>Executive Summary</h3></EuiTitle>
                    <EuiSpacer size="s" />
                    <EuiFlexGrid columns={4}>
                      <EuiCard title={<EuiStat title={reportView.executive_summary?.total_events || 0} description="Events" />} description="" />
                      <EuiCard title={<EuiStat title={reportView.executive_summary?.campaigns || 0} description="Campaigns" />} description="" />
                      <EuiCard title={<EuiStat title={reportView.executive_summary?.high_risk_campaigns || 0} description="High Risk" />} description="" />
                      <EuiCard title={<EuiStat title={reportView.executive_summary?.mitre_techniques || 0} description="MITRE Techniques" />} description="" />
                    </EuiFlexGrid>
                  </EuiPanel>

                  <EuiSpacer />

                  <EuiPanel>
                    <EuiTitle size="s"><h3>Key Findings</h3></EuiTitle>
                    <EuiSpacer size="s" />
                    <EuiText>
                      <ul>
                        {(reportView.key_findings || []).map((x: string) => <li key={x}>{x}</li>)}
                      </ul>
                    </EuiText>
                  </EuiPanel>

                  <EuiSpacer />

                  <EuiPanel>
                    <EuiTitle size="s"><h3>Top Campaigns</h3></EuiTitle>
                    <EuiSpacer size="s" />
                    <EuiBasicTable
                      items={paginate(reportView.top_campaigns || [], reportCampaignPage, 5)}
                      columns={[
                        { field: 'agent', name: 'Agent' },
                        { field: 'srcip', name: 'Src IP' },
                        { field: 'event_count', name: 'Events' },
                        { field: 'techniques', name: 'Techniques' },
                        { field: 'confidence', name: 'Confidence', render: (v: number) => `${v}%` },
                        { field: 'risk_score', name: 'Risk', render: (v: number) => <EuiBadge color={riskColor(v)}>{v}</EuiBadge> },
                      ]}
                    />
                    <EuiFlexGroup justifyContent="flexEnd" alignItems="center" gutterSize="s">
                      <EuiFlexItem grow={false}>
                        <EuiText size="s">Page {reportCampaignPage + 1} / {pageCount(reportView.top_campaigns || [], 5)}</EuiText>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButtonEmpty size="xs" disabled={reportCampaignPage === 0} onClick={() => setReportCampaignPage(Math.max(0, reportCampaignPage - 1))}>Previous</EuiButtonEmpty>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButtonEmpty size="xs" disabled={reportCampaignPage + 1 >= pageCount(reportView.top_campaigns || [], 5)} onClick={() => setReportCampaignPage(reportCampaignPage + 1)}>Next</EuiButtonEmpty>
                      </EuiFlexItem>
                    </EuiFlexGroup>
                  </EuiPanel>

                  <EuiSpacer />

                  <EuiPanel>
                    <EuiTitle size="s"><h3>ATT&CK Chain</h3></EuiTitle>
                    <EuiSpacer size="s" />
                    <EuiBasicTable
                      items={paginate(reportView.attack_chain || [], reportChainPage, 8)}
                      columns={[
                        { field: 'technique_id', name: 'Technique' },
                        { field: 'name', name: 'Name' },
                        { field: 'tactics', name: 'Tactics', render: (v: any) => arr(v).join(', ') },
                        { field: 'atomic_tests', name: 'Atomic Tests' },
                        { field: 'attack_flow_refs', name: 'Attack Flow Refs' },
                      ]}
                    />
                    <EuiFlexGroup justifyContent="flexEnd" alignItems="center" gutterSize="s">
                      <EuiFlexItem grow={false}>
                        <EuiText size="s">Page {reportChainPage + 1} / {pageCount(reportView.attack_chain || [], 8)}</EuiText>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButtonEmpty size="xs" disabled={reportChainPage === 0} onClick={() => setReportChainPage(Math.max(0, reportChainPage - 1))}>Previous</EuiButtonEmpty>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButtonEmpty size="xs" disabled={reportChainPage + 1 >= pageCount(reportView.attack_chain || [], 8)} onClick={() => setReportChainPage(reportChainPage + 1)}>Next</EuiButtonEmpty>
                      </EuiFlexItem>
                    </EuiFlexGroup>
                  </EuiPanel>

                  <EuiSpacer />

                  <EuiPanel>
                    <EuiTitle size="s"><h3>IOC Summary</h3></EuiTitle>
                    <EuiSpacer size="s" />
                    {Object.entries(reportView.ioc_summary || {}).map(([k, values]: any) => (
                      <div key={k} style={{ marginBottom: 12 }}>
                        <EuiText size="s"><b>{k.toUpperCase()}</b></EuiText>
                        {(values || []).map((x: string) => (
                          <EuiBadge key={x} color="hollow" style={{ margin: 3 }}>{x}</EuiBadge>
                        ))}
                      </div>
                    ))}
                  </EuiPanel>

                  <EuiSpacer />

                  <EuiPanel>
                    <EuiTitle size="s"><h3>MITRE Recommendations</h3></EuiTitle>
                    <EuiSpacer size="s" />
                    {paginate(reportView.recommendations || [], reportRecommendationPage, 5).map((r: any) => (
                      <EuiPanel key={r.technique_id} color="subdued" style={{ marginBottom: 10 }}>
                        <EuiText size="s">
                          <h4>{r.technique_id} — {r.technique_name}</h4>
                          {(r.mitigations || []).slice(0, 5).map((m: any) => (
                            <p key={m.mitigation_id}>- {m.mitigation_id}: {m.name}</p>
                          ))}
                        </EuiText>
                      </EuiPanel>
                    ))}
                    <EuiFlexGroup justifyContent="flexEnd" alignItems="center" gutterSize="s">
                      <EuiFlexItem grow={false}>
                        <EuiText size="s">Page {reportRecommendationPage + 1} / {pageCount(reportView.recommendations || [], 5)}</EuiText>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButtonEmpty size="xs" disabled={reportRecommendationPage === 0} onClick={() => setReportRecommendationPage(Math.max(0, reportRecommendationPage - 1))}>Previous</EuiButtonEmpty>
                      </EuiFlexItem>
                      <EuiFlexItem grow={false}>
                        <EuiButtonEmpty size="xs" disabled={reportRecommendationPage + 1 >= pageCount(reportView.recommendations || [], 5)} onClick={() => setReportRecommendationPage(reportRecommendationPage + 1)}>Next</EuiButtonEmpty>
                      </EuiFlexItem>
                    </EuiFlexGroup>
                  </EuiPanel>
                </>
              ) : (
                <EuiText>No structured report data available.</EuiText>
              )}
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiFlexGroup justifyContent="spaceBetween">
                <EuiFlexItem grow={false}>
                  <EuiButtonEmpty href={reportDownloadUrl(reportTitle)}>Download</EuiButtonEmpty>
                </EuiFlexItem>
                <EuiFlexItem grow={false}>
                  <EuiButton onClick={() => setShowReport(false)}>Close</EuiButton>
                </EuiFlexItem>
              </EuiFlexGroup>
            </EuiFlyoutFooter>
          </EuiFlyout>
        )}

        {drawerCampaign && (
          <EuiFlyout onClose={() => setDrawerCampaign(null)} size="l">
            <EuiFlyoutHeader hasBorder>
              <EuiTitle size="m">
                <h2>Campaign Details: {drawerCampaign.agent} / {drawerCampaign.srcip}</h2>
              </EuiTitle>
            </EuiFlyoutHeader>
            <EuiFlyoutBody>
              <EuiText>
                <p><b>Risk:</b> <EuiBadge color={riskColor(drawerCampaign.risk_score)}>{drawerCampaign.risk_score}</EuiBadge></p>
                <p><b>Confidence:</b> {drawerCampaign.confidence}%</p>
                <p><b>Events:</b> {drawerCampaign.event_count}</p>
              </EuiText>

              <EuiHorizontalRule />

              <EuiTitle size="s"><h3>Observed Techniques & Evidence</h3></EuiTitle>
              <EuiSpacer size="s" />

              {(drawerCampaign.chain || []).map((t: any) => {
                const evs = evidenceForTechnique(drawerCampaign.events || [], t.technique_id);
                return (
                  <EuiPanel key={t.technique_id} color="subdued" style={{ marginBottom: 12 }}>
                    <EuiText size="s">
                      <h4>{t.technique_id} — {t.name}</h4>
                      <p><b>Tactic:</b> {arr(t.tactics).join(', ') || '-'}</p>
                      <p><b>Evidence events:</b> {countTechniqueEvents(drawerCampaign.events || [], t.technique_id)}</p>
                      {evs.map((e, idx) => (
                        <p key={idx}>
                          - Rule {e.rule}, level {e.level}, {formatTime(e.time)}, srcip={e.srcip}, url={e.url}, {e.description}
                        </p>
                      ))}
                    </EuiText>
                  </EuiPanel>
                );
              })}

              <EuiHorizontalRule />

              <EuiTitle size="s"><h3>Campaign IOC</h3></EuiTitle>
              <EuiSpacer size="s" />
              {Object.entries(campaignIocs).map(([k, values]: any) => (
                <EuiPanel key={k} color="subdued" style={{ marginBottom: 10 }}>
                  <EuiText size="s"><b>{k.toUpperCase()}</b></EuiText>
                  {(values || []).map((x: string) => (
                    <EuiButtonEmpty key={x} size="xs" onClick={() => setPivot(x)}>{x}</EuiButtonEmpty>
                  ))}
                </EuiPanel>
              ))}

              <EuiHorizontalRule />

              <EuiTitle size="s"><h3>MITRE Recommendations</h3></EuiTitle>
              <EuiSpacer size="s" />
              {recommendationsForSelected.slice(0, 8).map((r: any) => (
                <EuiPanel key={r.technique_id} color="subdued" style={{ marginBottom: 10 }}>
                  <EuiText size="s">
                    <h4>{r.technique_id} — {r.technique_name}</h4>
                    {(r.mitigations || []).slice(0, 6).map((m: any) => (
                      <p key={m.mitigation_id}>- {m.mitigation_id}: {m.name}</p>
                    ))}
                  </EuiText>
                </EuiPanel>
              ))}
            </EuiFlyoutBody>
            <EuiFlyoutFooter>
              <EuiButton onClick={() => setDrawerCampaign(null)}>Close</EuiButton>
            </EuiFlyoutFooter>
          </EuiFlyout>
        )}
      </>
    </Router>
  );
};
