export function Card({ children, className }) {
  return <div className={`rounded-lg p-4 ${className}`}>{children}</div>;
}