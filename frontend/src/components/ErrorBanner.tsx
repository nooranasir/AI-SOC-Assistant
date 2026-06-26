type ErrorBannerProps = {
  message: string;
};

export default function ErrorBanner({ message }: ErrorBannerProps): React.ReactElement {
  return (
    <div className="error-banner" role="alert">
      <strong>Request failed</strong>
      <p>{message}</p>
    </div>
  );
}
