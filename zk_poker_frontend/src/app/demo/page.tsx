/**
 * Demo Page - Live visualization of zero-knowledge poker protocol
 */

import { EmbeddedDemoScene } from '~/components/demo/EmbeddedDemoScene';

export const metadata = {
  title: 'Live Demo | LegitPoker',
  description: 'Watch zero-knowledge mental poker in action',
};

export default function DemoPage() {
  return (
    <div
      style={{
        width: '100vw',
        height: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: '#0a0e14',
        overflow: 'hidden',
      }}
    >
      <EmbeddedDemoScene
        isActive={true}
        showBackground={true}
        containerStyle={{
          width: '100%',
          height: '100%',
        }}
      />
    </div>
  );
}
