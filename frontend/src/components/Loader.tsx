export default function Loader({ label = 'Loading' }: { label?: string }): React.ReactElement {
  return (
    <div className="loader" aria-live="polite" aria-busy="true">
      <span className="loader-dot" />
      <span className="loader-dot" />
      <span className="loader-dot" />
      <span>{label}</span>
    </div>
  );
}
