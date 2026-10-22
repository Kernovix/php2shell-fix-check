/* The page never contacts audit targets or sends report data anywhere. */
"use strict";

document.querySelectorAll("[data-copy]").forEach((button) => {
  button.hidden = false;
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copy);
    const status = document.getElementById("copy-status");
    if (!source || !status) return;
    try {
      if (!navigator.clipboard || !window.isSecureContext) throw new Error("Clipboard unavailable");
      await navigator.clipboard.writeText(source.textContent);
      button.textContent = "Copied";
      status.textContent = "Command copied. Replace the example targets with your authorized scope.";
      window.setTimeout(() => { button.textContent = "Copy"; }, 2200);
    } catch {
      const selection = window.getSelection();
      if (selection) {
        const range = document.createRange();
        range.selectNodeContents(source);
        selection.removeAllRanges();
        selection.addRange(range);
      }
      status.textContent = "Automatic copying is unavailable. Select and copy the command manually.";
      button.textContent = "Select";
    }
  });
});
