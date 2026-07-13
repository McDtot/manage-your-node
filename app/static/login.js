const form = document.querySelector("#loginForm");
const error = document.querySelector("#loginError");
const params = new URLSearchParams(window.location.search);
const next = params.get("next") || "/";

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
