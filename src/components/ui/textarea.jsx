export function Textarea({ placeholder, value, onChange }) {
  return (
    <textarea
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      className="w-full px-3 py-2 border rounded-md"
    />
  );
}