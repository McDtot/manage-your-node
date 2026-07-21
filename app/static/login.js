const form = document.querySelector("#loginForm");
const error = document.querySelector("#loginError");
const params = new URLSearchParams(window.location.search);
const next = params.get("next") || "/";

/* Liquid Glass：登录面板 3D 视差倾斜（仅精确指针 + 允许动态效果时启用） */
const shell = document.querySelector(".login-shell");
const finePointer = window.matchMedia("(pointer: fine)").matches;
const motionAllowed = window.matchMedia("(prefers-reduced-motion: no-preference)").matches;

if (shell && finePointer && motionAllowed) {
  const MAX_TILT_DEG = 4;
  const clamp = (value) => Math.max(-1, Math.min(1, value));

  shell.addEventListener("pointermove", (event) => {
    const rect = form.getBoundingClientRect();
    const offsetX = (event.clientX - (rect.left + rect.width / 2)) / (window.innerWidth / 2);
    const offsetY = (event.clientY - (rect.top + rect.height / 2)) / (window.innerHeight / 2);
    const rotateX = (-clamp(offsetY) * MAX_TILT_DEG).toFixed(2);
    const rotateY = (clamp(offsetX) * MAX_TILT_DEG).toFixed(2);
    form.style.transform = `perspective(900px) rotateX(${rotateX}deg) rotateY(${rotateY}deg)`;
  });

  shell.addEventListener("pointerleave", () => {
    form.style.transform = "";
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  error.hidden = true;
  const button = form.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const payload = Object.fromEntries(new FormData(form).entries());
    const response = await fetch("/api/auth/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      error.textContent = data.error || "登录失败";
      error.hidden = false;
      return;
    }
    window.location.href = next.startsWith("/") && !next.startsWith("//") ? next : "/";
  } catch (_error) {
    error.textContent = "无法连接管理服务";
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
});
