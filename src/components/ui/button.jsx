export function Button({ children, onClick, className }) {
  return (
    <button 
      className={`px-4 py-2 text-white rounded hover:bg-opacity-90 ${className}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
}