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
  badge: 'Beta',
  teaser: 'Get early access to LegitPoker →',
  href: '/launch-updates',
  analyticsEvent: 'announcement_ribbon_click',
  page: {
    title: 'Join the LegitPoker waitlist',
    description:
      'Be the first to know when we open tables. Get early access to cryptographically fair, bot-free poker with 2.5% rake.',
    ctaLabel: 'Continue to Typeform',
    typeformUrl: 'https://typeform.com/to/proofplay-launch',
    analyticsEvent: 'launch_updates_typeform_click',
  },
};
