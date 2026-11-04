// Progressive enhancement only: the site reads the same without this file.
// It adds a "Copy" button to code blocks that ask for one (pre[data-copy]).
(() => {
  if (!navigator.clipboard) return;
  for (const pre of document.querySelectorAll("pre[data-copy]")) {
    const wrap = document.createElement("div");
    wrap.className = "copyable";
    pre.replaceWith(wrap);
    wrap.append(pre);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.setAttribute("aria-label", "Copy the code block to the clipboard");

    const status = document.createElement("span");
    status.setAttribute("role", "status");
    status.style.cssText = "position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)";

    let timer;
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pre.innerText.replace(/\n$/, ""));
        button.textContent = "Copied";
        status.textContent = "Copied to the clipboard";
      } catch {
        button.textContent = "Press Ctrl+C";
        status.textContent = "Copying failed";
      }
      clearTimeout(timer);
      timer = setTimeout(() => {
        button.textContent = "Copy";
        status.textContent = "";
      }, 2000);
    });
    wrap.append(button, status);
  }
})();
