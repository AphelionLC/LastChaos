import * as RadixSelect from '@radix-ui/react-select';

export function Select({ options, onValueChange, placeholder }) {
  return (
    <RadixSelect.Root onValueChange={onValueChange}>
      <RadixSelect.Trigger className="inline-flex items-center justify-between rounded px-4 py-2 text-sm bg-white border">
        <RadixSelect.Value placeholder={placeholder} />
      </RadixSelect.Trigger>
      <RadixSelect.Portal>
        <RadixSelect.Content className="overflow-hidden bg-white rounded-md shadow-lg">
          <RadixSelect.Viewport className="p-2">
            {options.map((option) => (
              <RadixSelect.Item key={option.value} value={option.value} className="relative flex items-center px-8 py-2 text-sm rounded-md hover:bg-gray-100 cursor-pointer">
                <RadixSelect.ItemText>{option.label}</RadixSelect.ItemText>
              </RadixSelect.Item>
            ))}
          </RadixSelect.Viewport>
        </RadixSelect.Content>
      </RadixSelect.Portal>
    </RadixSelect.Root>
  );
}