import type { ReactElement } from 'react';

type StatusBlockProps = {
  title: string;
  value: string;
  tone?: 'neutral' | 'good' | 'warning' | 'critical';
};

export default function StatusBlock({ title, value, tone = 'neutral' }: StatusBlockProps): ReactElement {
  return (
    <div className={`status-block tone-${tone}`}>
      <span>{title}</span>
      <strong>{value}</strong>
    </div>
  );
}
