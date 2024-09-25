import * as RadixDialog from '@radix-ui/react-dialog';

export function Dialog({ children, open, onOpenChange }) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      <RadixDialog.Portal>
        <RadixDialog.Overlay className="bg-black/50 fixed inset-0" />
        <RadixDialog.Content className="fixed top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 bg-white rounded-lg p-6 w-full max-w-md">
          {children}
        </RadixDialog.Content>
      </RadixDialog.Portal>
    </RadixDialog.Root>
  );
}

Dialog.Content = ({ children }) => <div>{children}</div>;
Dialog.Header = ({ children }) => <div className="mb-4">{children}</div>;
Dialog.Title = ({ children }) => <h2 className="text-lg font-bold">{children}</h2>;
Dialog.Footer = ({ children }) => <div className="mt-4 flex justify-end space-x-2">{children}</div>;