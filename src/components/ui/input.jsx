export function Input({ placeholder, value, onChange }) {
  return (
    <input
      type="text"
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      className="w-full px-3 py-2 border rounded-md"
    />
  );
}