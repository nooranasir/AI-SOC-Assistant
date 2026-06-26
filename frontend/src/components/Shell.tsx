import type { ReactElement, ReactNode } from 'react';

type ShellProps = {
  title: string;
  subtitle: string;
  children: ReactNode;
};

export default function Shell({ title, subtitle, children }: ShellProps): ReactElement {
  return (
    <section className="page-shell">
      <header className="page-header panel">
        <div>
          <p className="eyebrow">Operational View</p>
          <h2>{title}</h2>
          <p className="page-subtitle">{subtitle}</p>
        </div>
      </header>
      {children}
    </section>
  );
}
