const host = document.createElement("div");
host.id = "tlsdebug-navigation-controls";

const shadow = host.attachShadow({ mode: "closed" });
const style = document.createElement("style");
style.textContent = `
  :host {
    all: initial;
    position: fixed;
    top: 12px;
    left: 12px;
    z-index: 2147483647;
  }

  button {
    width: 42px;
    height: 42px;
    padding: 0;
    border: 1px solid rgba(255, 255, 255, 0.25);
    border-radius: 21px;
    background: rgba(13, 17, 23, 0.88);
    color: #f0f6fc;
    box-shadow: 0 3px 12px rgba(0, 0, 0, 0.35);
    cursor: pointer;
    font: 26px/40px system-ui, sans-serif;
    text-align: center;
  }

  button:hover {
    background: rgba(48, 54, 61, 0.96);
  }

  button:focus-visible {
    outline: 2px solid #58a6ff;
    outline-offset: 2px;
  }
`;

const backButton = document.createElement("button");
backButton.type = "button";
backButton.title = "Go back";
backButton.setAttribute("aria-label", "Go back");
backButton.textContent = "←";
backButton.addEventListener("click", () => window.history.back());

shadow.append(style, backButton);

function mount() {
  if (!document.documentElement.contains(host)) {
    document.documentElement.append(host);
  }
}

mount();
document.addEventListener("DOMContentLoaded", mount, { once: true });
