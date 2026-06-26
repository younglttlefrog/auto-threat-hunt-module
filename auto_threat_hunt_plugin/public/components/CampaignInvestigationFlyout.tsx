import React from 'react';
import {
  EuiBadge,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutHeader,
  EuiTitle,
  EuiText,
  EuiSpacer,
} from '@elastic/eui';

import { CampaignDetails } from './CampaignDetails';

export const CampaignInvestigationFlyout = ({
  campaign,
  onClose,
}: {
  campaign: any;
  onClose: () => void;
}) => {
  if (!campaign) return null;

  return (
    <EuiFlyout
      onClose={onClose}
      size="80%"
      ownFocus
      aria-labelledby="campaignInvestigationFlyoutTitle"
    >
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="m">
          <h2 id="campaignInvestigationFlyoutTitle">
            Campaign Details: {campaign.agent || '-'} / {campaign.srcip || '-'}
          </h2>
        </EuiTitle>

        <EuiSpacer size="s" />

        <EuiText size="s">
          <EuiBadge color="hollow">{campaign.campaign_type || 'unknown'}</EuiBadge>
          {' '}
          <EuiBadge color={campaign.risk_score >= 80 ? 'danger' : campaign.risk_score >= 60 ? 'warning' : 'primary'}>
            Risk {campaign.risk_score}
          </EuiBadge>
          {' '}
          <EuiBadge color="hollow">
            Confidence {campaign.confidence}%
          </EuiBadge>
          {' '}
          <EuiBadge color="hollow">
            Events {campaign.event_count}
          </EuiBadge>
        </EuiText>
      </EuiFlyoutHeader>

      <EuiFlyoutBody>
        <CampaignDetails campaign={campaign} />
      </EuiFlyoutBody>
    </EuiFlyout>
  );
};
