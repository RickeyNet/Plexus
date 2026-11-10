import { Callout } from './Callout';

interface Props {
  /** Name of the feature, e.g. "Federation". Used in the headline. */
  feature: string;
}

/**
 * Prominent, always-visible warning shown at the top of experimental pages
 * whose functionality has not been validated yet. Unlike PageHelp it cannot be
 * dismissed — the disclaimer should stay visible while the feature is untested.
 */
export function UntestedBanner({ feature }: Props) {
  return (
    <Callout tone="warning" title={`${feature} has not been tested yet.`}>
      This feature is experimental and hidden by default. Its behaviour may be
      incomplete or change without notice — verify any results before relying
      on them in production.
    </Callout>
  );
}
