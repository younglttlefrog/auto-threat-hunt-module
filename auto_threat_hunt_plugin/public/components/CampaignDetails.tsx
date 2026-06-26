import React from 'react';
import {
  EuiAccordion,
  EuiBadge,
  EuiBasicTable,
  EuiCallOut,
  EuiCodeBlock,
  EuiDescriptionList,
  EuiFlexGroup,
  EuiFlexItem,
  EuiHorizontalRule,
  EuiPanel,
  EuiSpacer,
  EuiTabbedContent,
  EuiText,
  EuiTitle,
} from '@elastic/eui';

const arr = (v: any) => Array.isArray(v) ? v : v ? [v] : [];

const riskColor = (v: number) => {
  if (v >= 80) return 'danger';
  if (v >= 60) return 'warning';
  if (v >= 40) return 'primary';
  return 'success';
};

const priorityColor = (p: string) => {
  if (p === 'critical' || p === 'high') return 'danger';
  if (p === 'medium') return 'warning';
  return 'hollow';
};

const compactEvent = (e: any) =>
  `Rule ${e.rule_id || '-'}, level ${e.level ?? '-'}, ${e.timestamp || '-'}, srcip=${e.srcip || '-'}, url=${e.url || '-'}, ${e.description || '-'}`;

const buildOpenSearchQuery = (campaign: any) => {
  const agent = campaign.agent && campaign.agent !== '-' ? campaign.agent : null;
  const srcip = campaign.srcip && campaign.srcip !== '-' ? campaign.srcip : null;

  const should: any[] = [];

  if (agent) should.push({ term: { 'agent.name': agent } });
  if (srcip) should.push({ term: { 'data.srcip': srcip } });

  const ruleIds = Array.from(
    new Set(
      (campaign.events || [])
        .map((e: any) => String(e.rule_id || ''))
        .filter((x: string) => x && x !== '-' && x !== 'archive')
    )
  );

  if (ruleIds.length) should.push({ terms: { 'rule.id': ruleIds } });

  const mitreIds = Array.from(
    new Set(
      (campaign.chain || [])
        .map((c: any) => c.technique_id)
        .filter((x: string) => x)
    )
  );

  if (mitreIds.length) should.push({ terms: { 'rule.mitre.id': mitreIds } });

  return JSON.stringify(
    {
      size: 100,
      sort: [{ '@timestamp': { order: 'asc' } }],
      _source: [
        '@timestamp',
        'agent.name',
        'rule.id',
        'rule.level',
        'rule.description',
        'rule.mitre.id',
        'rule.mitre.tactic',
        'data.srcip',
        'data.user',
        'data.srcuser',
        'data.url',
        'full_log',
      ],
      query: {
        bool: {
          should,
          minimum_should_match: should.length ? 1 : 0,
        },
      },
    },
    null,
    2
  );
};

const buildCurlQuery = (campaign: any) => {
  const query = buildOpenSearchQuery(campaign).replace(/'/g, "'\\''");

  return `curl -k -u admin:'<OPENSEARCH_PASSWORD>' \\
https://127.0.0.1:9200/wazuh-alerts-*/_search \\
-H 'Content-Type: application/json' \\
-d '${query}'`;
};

const scoreRows = (score: any, campaign: any) => [
  {
    metric: 'Max Level Score',
    value: score.max_level ?? '-',
    description: 'Contribution from the highest Wazuh alert level observed in this campaign.',
  },
  {
    metric: 'Event Volume',
    value: score.event_volume ?? '-',
    description: 'Score added from the number of correlated events in the campaign.',
  },
  {
    metric: 'Technique Score',
    value: score.technique_score ?? '-',
    description: 'Points awarded from the number of observed MITRE ATT&CK techniques.',
  },
  {
    metric: 'Tactic Score',
    value: score.tactic_score ?? '-',
    description: 'Points awarded from ATT&CK tactic coverage.',
  },
  {
    metric: 'Confidence Score',
    value: score.confidence_score ?? '-',
    description: 'Score derived from evidence confidence and attack-chain reconstruction.',
  },
  {
    metric: 'High Risk Bonus',
    value: score.high_risk_bonus ?? '-',
    description: 'Bonus applied when high-impact techniques are observed.',
  },
  {
    metric: 'Raw Score',
    value: score.raw_score_before_caps ?? '-',
    description: 'Risk score before applying false-positive reduction caps.',
  },
  {
    metric: 'Final Score',
    value: score.final_score ?? campaign.risk_score,
    description: 'Final normalized campaign risk score after calibration and caps.',
  },
];

export const CampaignDetails = ({ campaign }: { campaign: any }) => {
  if (!campaign) {
    return (
      <EuiCallOut title="No campaign selected" color="warning">
        Select a campaign to view investigation details.
      </EuiCallOut>
    );
  }

  const summary = campaign.evidence_summary || {};
  const score = campaign.score_breakdown || {};
  const actions = campaign.recommended_actions || [];

  const actionRows = actions.flatMap((pb: any) =>
    (pb.recommended_actions || []).map((a: any, idx: number) => ({
      id: `${pb.technique_id}-${idx}`,
      technique: pb.technique_id,
      technique_name: pb.technique_name,
      priority: a.priority,
      stage: a.stage,
      action: a.action,
      reason: a.reason,
      safe_mode: a.safe_mode,
      commands: arr(a.commands),
      source: pb.source,
      key_indicators: pb.key_indicators || [],
      escalate_if: pb.escalate_if || [],
    }))
  );

  const overview = (
    <>
      <EuiFlexGroup alignItems="stretch">
        <EuiFlexItem grow={1}>
          <EuiPanel hasShadow={true}>
            <EuiTitle size="s"><h3>Campaign Summary</h3></EuiTitle>
            <EuiSpacer size="s" />
            <EuiDescriptionList
              type="column"
              listItems={[
                { title: 'Campaign Type', description: <EuiBadge color="hollow">{campaign.campaign_type || 'unknown'}</EuiBadge> },
                { title: 'Risk', description: <EuiBadge color={riskColor(campaign.risk_score)}>{campaign.risk_score}</EuiBadge> },
                { title: 'Confidence', description: `${campaign.confidence}%` },
                { title: 'Agent', description: campaign.agent || '-' },
                { title: 'Source IP', description: campaign.srcip || '-' },
                { title: 'Events', description: campaign.event_count || 0 },
              ]}
            />
          </EuiPanel>
        </EuiFlexItem>

        <EuiFlexItem grow={2}>
          <EuiPanel hasShadow={true}>
            <EuiTitle size="s"><h3>Why this matters</h3></EuiTitle>
            <EuiSpacer size="s" />
            <EuiCallOut title={summary.hypothesis || 'Analyst review required'} color="primary">
              <p>{summary.reason || 'This campaign contains correlated security events that require analyst review.'}</p>
            </EuiCallOut>
          </EuiPanel>
        </EuiFlexItem>
      </EuiFlexGroup>

      <EuiSpacer />

      <EuiPanel hasShadow={true}>
        <EuiTitle size="s"><h3>Risk Factors</h3></EuiTitle>
        <EuiText size="s">
          <ul>{arr(summary.risk_factors).map((x: string, i: number) => <li key={i}>{x}</li>)}</ul>
        </EuiText>

        <EuiHorizontalRule margin="s" />

        <EuiTitle size="xs"><h4>Limitations</h4></EuiTitle>
        <EuiText size="s">
          <ul>{arr(summary.limitations).map((x: string, i: number) => <li key={i}>{x}</li>)}</ul>
        </EuiText>
      </EuiPanel>
    </>
  );

  const evidence = (
    <EuiPanel hasShadow={true}>
      <EuiTitle size="s"><h3>Score Breakdown</h3></EuiTitle>
      <EuiSpacer size="s" />
      <EuiBasicTable
        items={scoreRows(score, campaign)}
        columns={[
          { field: 'metric', name: 'Metric', width: '180px' },
          { field: 'value', name: 'Value', width: '90px' },
          { field: 'description', name: 'Description' },
        ]}
      />
      <EuiHorizontalRule margin="s" />
      <EuiText size="s">
        <b>Caps Applied:</b>{' '}
        {arr(score.caps_applied).length ? arr(score.caps_applied).join(', ') : 'None'}
      </EuiText>
    </EuiPanel>
  );

  const chain = (
    <EuiPanel hasShadow={true}>
      <EuiTitle size="s"><h3>ATT&CK Chain Evidence</h3></EuiTitle>
      <EuiSpacer size="s" />
      <EuiBasicTable
        items={campaign.chain || []}
        columns={[
          { field: 'technique_id', name: 'Technique', width: '120px' },
          { field: 'name', name: 'Name' },
          { field: 'event_count', name: 'Events', width: '90px' },
          { field: 'rule_ids', name: 'Rules', render: (v: any) => arr(v).join(', ') || '-' },
          { field: 'tactics', name: 'Tactics', render: (v: any) => arr(v).join(', ') || '-' },
        ]}
        pagination={{ pageSize: 10 }}
      />

      <EuiSpacer />

      <EuiTitle size="s"><h3>Observed Techniques & Evidence</h3></EuiTitle>
      <EuiSpacer size="s" />

      {(campaign.chain || []).map((t: any) => (
        <EuiPanel key={t.technique_id} color="subdued" paddingSize="m">
          <EuiText size="s">
            <h4>{t.technique_id} — {t.name}</h4>
            <p><b>Tactic:</b> {arr(t.tactics).join(', ') || '-'}</p>
            <p><b>Evidence events:</b> {t.event_count}</p>
            <ul>
              {(campaign.events || [])
                .filter((e: any) => arr(e.mitre_id).includes(t.technique_id))
                .slice(0, 5)
                .map((e: any, i: number) => <li key={i}>{compactEvent(e)}</li>)}
            </ul>
          </EuiText>
        </EuiPanel>
      ))}
    </EuiPanel>
  );

  const analystActions = (
    <EuiPanel hasShadow={true}>
      <EuiTitle size="s"><h3>Recommended Analyst Actions</h3></EuiTitle>
      <EuiSpacer size="s" />

      {actionRows.length === 0 && (
        <EuiCallOut title="No recommended actions available" color="warning">
          No response playbook was mapped to this campaign.
        </EuiCallOut>
      )}

      {actionRows.map((a: any, idx: number) => (
        <div key={a.id}>
          <EuiAccordion
            id={`analyst-action-${a.id}`}
            buttonContent={
              <span>
                <EuiBadge color={priorityColor(a.priority)}>{a.priority}</EuiBadge>
                {' '}
                <strong>{a.technique}</strong>
                {' '}
                <span>{a.action}</span>
              </span>
            }
            paddingSize="m"
          >
            <EuiPanel color="subdued" paddingSize="m">
              <EuiDescriptionList
                type="column"
                listItems={[
                  { title: 'Technique', description: `${a.technique} ${a.technique_name || ''}` },
                  { title: 'Stage', description: a.stage || '-' },
                  { title: 'Reason', description: a.reason || '-' },
                  { title: 'Safe Mode', description: a.safe_mode || '-' },
                  { title: 'Source', description: a.source || '-' },
                ]}
              />

              {arr(a.commands).length > 0 && (
                <>
                  <EuiSpacer size="s" />
                  <EuiTitle size="xs"><h4>Commands / Checks</h4></EuiTitle>
                  <EuiCodeBlock language="bash" fontSize="s" paddingSize="s">
                    {arr(a.commands).join('\n')}
                  </EuiCodeBlock>
                </>
              )}

              {arr(a.key_indicators).length > 0 && (
                <>
                  <EuiSpacer size="s" />
                  <EuiTitle size="xs"><h4>Key Indicators</h4></EuiTitle>
                  <EuiText size="s">
                    <ul>{arr(a.key_indicators).slice(0, 5).map((x: string, i: number) => <li key={i}>{x}</li>)}</ul>
                  </EuiText>
                </>
              )}

              {arr(a.escalate_if).length > 0 && (
                <>
                  <EuiSpacer size="s" />
                  <EuiTitle size="xs"><h4>Escalate If</h4></EuiTitle>
                  <EuiText size="s">
                    <ul>{arr(a.escalate_if).slice(0, 5).map((x: string, i: number) => <li key={i}>{x}</li>)}</ul>
                  </EuiText>
                </>
              )}
            </EuiPanel>
          </EuiAccordion>
          {idx < actionRows.length - 1 && <EuiHorizontalRule margin="s" />}
        </div>
      ))}
    </EuiPanel>
  );

  const rawLogs = (
    <>
      <EuiPanel hasShadow={true}>
        <EuiTitle size="s"><h3>Raw Event Evidence</h3></EuiTitle>
        <EuiSpacer size="s" />
        <EuiBasicTable
          items={campaign.events || []}
          columns={[
            { field: 'timestamp', name: 'Time', width: '210px' },
            { field: 'source', name: 'Source', width: '90px' },
            { field: 'rule_id', name: 'Rule', width: '90px' },
            { field: 'level', name: 'Level', width: '80px' },
            { field: 'mitre_id', name: 'MITRE', width: '160px', render: (v: any) => arr(v).join(', ') || '-' },
            { field: 'description', name: 'Description' },
          ]}
          pagination={{ pageSize: 10 }}
        />
      </EuiPanel>

      <EuiSpacer />

      <EuiPanel hasShadow={true}>
        <EuiTitle size="s"><h3>Pivot Query for OpenSearch</h3></EuiTitle>
        <EuiSpacer size="s" />

        <EuiText size="s">
          Use this query to manually pivot from the campaign back to Wazuh alerts in OpenSearch.
        </EuiText>

        <EuiSpacer size="s" />

        <EuiCodeBlock language="json" fontSize="s" paddingSize="s" isCopyable>
          {buildOpenSearchQuery(campaign)}
        </EuiCodeBlock>

        <EuiSpacer />

        <EuiTitle size="xs"><h4>cURL Query</h4></EuiTitle>
        <EuiCodeBlock language="bash" fontSize="s" paddingSize="s" isCopyable>
          {buildCurlQuery(campaign)}
        </EuiCodeBlock>
      </EuiPanel>

      <EuiSpacer />

      <EuiPanel hasShadow={true}>
        <EuiTitle size="s"><h3>Full Logs</h3></EuiTitle>
        <EuiSpacer size="s" />

        {(campaign.events || []).slice(0, 20).map((e: any, idx: number) => (
          <EuiAccordion
            key={idx}
            id={`raw-log-${idx}`}
            buttonContent={`Event ${idx + 1}: Rule ${e.rule_id || '-'} | ${e.timestamp || '-'}`}
            paddingSize="s"
          >
            <EuiCodeBlock language="json" fontSize="s" paddingSize="s" isCopyable>
              {JSON.stringify(e, null, 2)}
            </EuiCodeBlock>
          </EuiAccordion>
        ))}
      </EuiPanel>
    </>
  );

  return (
    <EuiTabbedContent
      tabs={[
        { id: 'overview', name: 'Overview', content: overview },
        { id: 'evidence', name: 'Evidence', content: evidence },
        { id: 'attack-chain', name: 'ATT&CK Chain', content: chain },
        { id: 'actions', name: 'Analyst Actions', content: analystActions },
        { id: 'raw-logs', name: 'Raw Logs / Pivot Query', content: rawLogs },
      ]}
      initialSelectedTab={{ id: 'overview', name: 'Overview', content: overview }}
    />
  );
};
