(() => {
  const button = document.getElementById('copy-command');
  if (!button) return;
  const command = document.getElementById('launch-command');
  const status = document.getElementById('copy-status');
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(command.textContent);
      status.textContent = 'Copied. Paste it in your terminal to start the proxy.';
      button.textContent = 'Copied';
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(command);
      selection.removeAllRanges();
      selection.addRange(range);
      command.focus();
      status.textContent = 'Select and copy the command with your keyboard.';
    }
  });
})();
