/**
 * Theme tones shared by the UI primitives.
 *
 * Class strings are spelled out in full so Tailwind can find them.
 */

export type Tone = 'primary' | 'accent' | 'success' | 'warning' | 'danger' | 'info' | 'muted';

export const TONE_TEXT: Record<Tone, string> = {
  primary: 'text-primary',
  accent: 'text-accent',
  success: 'text-success',
  warning: 'text-warning',
  danger: 'text-danger',
  info: 'text-info',
  muted: 'text-text-muted',
};

export const TONE_BG: Record<Tone, string> = {
  primary: 'bg-primary',
  accent: 'bg-accent',
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
  info: 'bg-info',
  muted: 'bg-text-muted',
};

export const TONE_BORDER: Record<Tone, string> = {
  primary: 'border-primary/40',
  accent: 'border-accent/40',
  success: 'border-success/40',
  warning: 'border-warning/40',
  danger: 'border-danger/40',
  info: 'border-info/40',
  muted: 'border-border',
};

export const TONE_GLOW_TEXT: Record<Tone, string> = {
  primary: 'glow-text-primary',
  accent: 'glow-text-accent',
  success: 'glow-text-success',
  warning: 'glow-text-warning',
  danger: 'glow-text-danger',
  info: 'glow-text-primary',
  muted: '',
};

/** CSS custom property for each tone, usable in inline SVG `stroke`/`fill` and `style`. */
export const TONE_VAR: Record<Tone, string> = {
  primary: 'var(--color-primary)',
  accent: 'var(--color-accent)',
  success: 'var(--color-success)',
  warning: 'var(--color-warning)',
  danger: 'var(--color-danger)',
  info: 'var(--color-info)',
  muted: 'var(--color-text-muted)',
};

export interface Thresholds {
  warn: number;
  crit: number;
}

export const DEFAULT_THRESHOLDS: Thresholds = { warn: 70, crit: 90 };

/** Map a utilisation value onto success / warning / danger. */
export function thresholdTone(value: number, thresholds: Thresholds = DEFAULT_THRESHOLDS): Tone {
  if (value >= thresholds.crit) return 'danger';
  if (value >= thresholds.warn) return 'warning';
  return 'success';
}
