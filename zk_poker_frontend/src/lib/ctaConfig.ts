export interface AnnouncementRibbonPageConfig {
  readonly title: string;
  readonly description: string;
  readonly ctaLabel: string;
  readonly typeformUrl: string;
  readonly analyticsEvent: string;
}

export interface AnnouncementRibbonConfig {
  readonly id: string;
  readonly badge: string;
  readonly teaser: string;
  readonly href: string;
  readonly analyticsEvent: string;
  readonly page: AnnouncementRibbonPageConfig;
}

export const announcementRibbon: AnnouncementRibbonConfig = {
  id: 'launch-announcements',
  badge: 'New',
  teaser: 'Sign up for launch announcements →',
  href: '/launch-updates',
  analyticsEvent: 'announcement_ribbon_click',
  page: {
    title: 'Be first to join the ProofPlay launch',
    description:
      'Get an email the moment we open private tables, share tournament invites, and publish the technical breakdown for investors.',
    ctaLabel: 'Continue to Typeform',
    typeformUrl: 'https://typeform.com/to/proofplay-launch',
    analyticsEvent: 'launch_updates_typeform_click',
  },
};
