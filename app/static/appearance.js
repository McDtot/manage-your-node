/* ---------------------------------------------------------------------------
 * 外观与背景（纯前端，localStorage 持久化）
 * - 预设渐变 / 上传图片（自动压缩到 1920px 宽）/ 图片 URL
 * - 遮罩强度滑块控制背景上的白色（暗色为黑色）薄纱，保证可读性
 * - 只写 body class 与 CSS 变量，不改动任何既有 id / class 契约
 * ------------------------------------------------------------------------- */
(() => {
  const KEY = "myn-appearance-v1";
  const THEME_KEY = "myn-theme-v1";
  const MAX_WIDTH = 1920;
  const JPEG_QUALITY = 0.82;

  /* ------------------------------------------------------------------
   * 主题：auto（跟随系统）/ light / dark，存 localStorage。
   * CSS 只认 html[data-theme="dark"]，auto 由这里解析成具体值。
   * ------------------------------------------------------------------ */
  const themeMedia = window.matchMedia("(prefers-color-scheme: dark)");

  function currentTheme() {
    try {
      return localStorage.getItem(THEME_KEY) || "auto";
    } catch {
      return "auto";
    }
  }

  function applyTheme() {
    const pref = currentTheme();
    const dark = pref === "dark" || (pref === "auto" && themeMedia.matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    const btn = document.getElementById("themeToggleBtn");
    if (btn) {
      const meta = {
        auto: ["🌓", "主题：跟随系统"],
        light: ["☀️", "主题：亮色"],
        dark: ["🌙", "主题：暗色"],
      }[pref];
      btn.textContent = meta[0];
      btn.title = `${meta[1]}（点击切换）`;
      btn.setAttribute("aria-label", meta[1]);
    }
  }

  applyTheme();
  if (themeMedia.addEventListener) {
    themeMedia.addEventListener("change", () => {
      if (currentTheme() === "auto") applyTheme();
    });
  }

  const themeBtn = document.getElementById("themeToggleBtn");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const order = ["auto", "light", "dark"];
      const next = order[(order.indexOf(currentTheme()) + 1) % order.length];
      try {
        localStorage.setItem(THEME_KEY, next);
      } catch {
        // 存储不可用时仅本次生效
      }
      applyTheme();
      notify({ auto: "主题：跟随系统", light: "主题：亮色", dark: "主题：暗色" }[next]);
    });
  }

  const PRESETS = [
    {
      id: "default",
      name: "默认光晕",
      value: "",
      swatch:
        "radial-gradient(circle at 80% 0%, rgba(74,92,255,.5), transparent 60%)," +
        "radial-gradient(circle at 0% 100%, rgba(31,182,224,.45), transparent 60%), #e9edf5",
    },
    {
      id: "aurora",
      name: "极光",
      value:
        "radial-gradient(60rem 42rem at 12% 8%, rgba(74,92,255,.85), transparent 62%)," +
        "radial-gradient(52rem 38rem at 88% 18%, rgba(31,182,224,.75), transparent 60%)," +
        "radial-gradient(58rem 44rem at 50% 108%, rgba(139,92,246,.8), transparent 66%)",
      color: "#101632",
      swatch:
        "radial-gradient(circle at 15% 10%, #4a5cff, transparent 60%)," +
        "radial-gradient(circle at 85% 20%, #1fb6e0, transparent 60%)," +
        "radial-gradient(circle at 50% 100%, #8b5cf6, transparent 65%), #101632",
    },
    {
      id: "sunset",
      name: "落日",
      value:
        "radial-gradient(58rem 40rem at 20% 0%, rgba(245,158,11,.8), transparent 62%)," +
        "radial-gradient(54rem 42rem at 85% 30%, rgba(239,68,68,.65), transparent 62%)," +
        "radial-gradient(60rem 46rem at 50% 110%, rgba(139,92,246,.75), transparent 66%)",
      color: "#2a1230",
      swatch:
        "radial-gradient(circle at 20% 0%, #f59e0b, transparent 60%)," +
        "radial-gradient(circle at 85% 30%, #ef4444, transparent 60%)," +
        "radial-gradient(circle at 50% 100%, #8b5cf6, transparent 65%), #2a1230",
    },
    {
      id: "ocean",
      name: "深海",
      value:
        "radial-gradient(58rem 42rem at 15% 15%, rgba(31,182,224,.7), transparent 62%)," +
        "radial-gradient(54rem 40rem at 85% 85%, rgba(31,191,107,.55), transparent 64%)," +
        "radial-gradient(50rem 38rem at 70% 0%, rgba(74,92,255,.6), transparent 62%)",
      color: "#06202b",
      swatch:
        "radial-gradient(circle at 15% 15%, #1fb6e0, transparent 60%)," +
        "radial-gradient(circle at 85% 85%, #1fbf6b, transparent 62%)," +
        "radial-gradient(circle at 70% 0%, #4a5cff, transparent 60%), #06202b",
    },
    {
      id: "wp-dawn",
      name: "晨曦",
      value: 'url("/static/wallpapers/dawn.png")',
      swatch: 'url("/static/wallpapers/dawn.png") center / cover',
    },
    {
      id: "wp-aurora",
      name: "深海极光",
      value: 'url("/static/wallpapers/aurora.png")',
      swatch: 'url("/static/wallpapers/aurora.png") center / cover',
    },
    {
      id: "wp-nebula",
      name: "紫雾",
      value: 'url("/static/wallpapers/nebula.png")',
      swatch: 'url("/static/wallpapers/nebula.png") center / cover',
    },
    {
      id: "wp-fjord",
      name: "峡湾",
      value: 'url("/static/wallpapers/photo-1015.jpg")',
      swatch: 'url("/static/wallpapers/photo-1015.jpg") center / cover',
    },
    {
      id: "wp-canyon",
      name: "峡谷暮色",
      value: 'url("/static/wallpapers/photo-1016.jpg")',
      swatch: 'url("/static/wallpapers/photo-1016.jpg") center / cover',
    },
    {
      id: "wp-lake",
      name: "山湖",
      value: 'url("/static/wallpapers/photo-1018.jpg")',
      swatch: 'url("/static/wallpapers/photo-1018.jpg") center / cover',
    },
    {
      id: "wp-snow",
      name: "雪山营地",
      value: 'url("/static/wallpapers/photo-1036.jpg")',
      swatch: 'url("/static/wallpapers/photo-1036.jpg") center / cover',
    },
    {
      id: "wp-falls",
      name: "森林瀑布",
      value: 'url("/static/wallpapers/photo-1039.jpg")',
      swatch: 'url("/static/wallpapers/photo-1039.jpg") center / cover',
    },
    {
      id: "graphite",
      name: "石墨",
      value:
        "radial-gradient(56rem 40rem at 80% -10%, rgba(148,163,184,.4), transparent 62%)," +
        "radial-gradient(50rem 38rem at 0% 100%, rgba(100,116,139,.35), transparent 62%)",
      color: "#10131a",
      swatch:
        "radial-gradient(circle at 80% 0%, #94a3b8, transparent 60%)," +
        "radial-gradient(circle at 0% 100%, #64748b, transparent 60%), #10131a",
    },
  ];

  const layer = document.getElementById("bgCustom");
  const body = document.body;

  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }

  function save(state) {
    try {
      if (!state || state.type === "default") {
        localStorage.removeItem(KEY);
      } else {
        localStorage.setItem(KEY, JSON.stringify(state));
      }
      return true;
    } catch {
      notify("图片太大，浏览器本地存储放不下，请换一张或改用 URL");
      return false;
    }
  }

  function notify(message) {
    const toast = document.getElementById("toast");
    if (!toast) return;
    toast.textContent = message;
    toast.hidden = false;
    clearTimeout(notify.timer);
    notify.timer = setTimeout(() => {
      toast.hidden = true;
    }, 2800);
  }

  function apply(state) {
    if (!layer) return;
    const veil = state && typeof state.veil === "number" ? state.veil : 35;
    body.style.setProperty("--bg-veil", (veil / 100).toFixed(2));
    // 卡片遮罩：未设置时移除内联变量，回退到样式表默认档位。
    // 滑块 10-90 映射为约 0.05-0.45 的填充透明度，保证任何档位都能透出背景模糊。
    if (state && typeof state.cardVeil === "number") {
      const alpha1 = (state.cardVeil / 100) * 0.5;
      body.style.setProperty("--glass-a1", alpha1.toFixed(2));
      body.style.setProperty("--glass-a2", (alpha1 * 0.45).toFixed(2));
    } else {
      body.style.removeProperty("--glass-a1");
      body.style.removeProperty("--glass-a2");
    }
    if (!state || state.type === "default") {
      body.classList.remove("has-custom-bg");
      layer.style.backgroundImage = "";
      layer.style.backgroundColor = "";
      return;
    }
    body.classList.add("has-custom-bg");
    if (state.type === "preset") {
      // background-image 不允许出现纯色，底色必须单独设置
      layer.style.backgroundImage = state.value;
      layer.style.backgroundColor = state.color || "";
    } else {
      layer.style.backgroundImage = `url("${state.value}")`;
      layer.style.backgroundColor = "";
    }
  }

  function readAndResize(file) {
    return new Promise((resolve, reject) => {
      const objectUrl = URL.createObjectURL(file);
      const img = new Image();
      img.onload = () => {
        const scale = Math.min(1, MAX_WIDTH / img.width);
        const canvas = document.createElement("canvas");
        canvas.width = Math.max(1, Math.round(img.width * scale));
        canvas.height = Math.max(1, Math.round(img.height * scale));
        canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height);
        URL.revokeObjectURL(objectUrl);
        resolve(canvas.toDataURL("image/jpeg", JPEG_QUALITY));
      };
      img.onerror = () => {
        URL.revokeObjectURL(objectUrl);
        reject(new Error("无法读取该图片"));
      };
      img.src = objectUrl;
    });
  }

  // 初始应用（登录页没有设置控件，只应用已保存的背景）
  const state = load();
  apply(state);

  const presetList = document.getElementById("bgPresetList");
  if (!presetList) return;

  const uploadBtn = document.getElementById("bgUploadBtn");
  const fileInput = document.getElementById("bgFileInput");
  const urlInput = document.getElementById("bgUrlInput");
  const urlApply = document.getElementById("bgUrlApply");
  const veilRange = document.getElementById("bgVeilRange");
  const cardVeilRange = document.getElementById("cardVeilRange");
  const resetBtn = document.getElementById("bgResetBtn");

  let current = state || { type: "default", veil: 35 };
  veilRange.value = String(current.veil ?? 35);
  cardVeilRange.value = String(current.cardVeil ?? 58);

  function commit(next) {
    if (!save(next)) return;
    current = next;
    apply(next);
    renderPresets();
  }

  function renderPresets() {
    presetList.textContent = "";
    for (const preset of PRESETS) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "bg-preset";
      btn.style.background = preset.swatch;
      if (current.type === "preset" && current.presetId === preset.id) {
        btn.classList.add("is-active");
      }
      if (current.type === "default" && preset.id === "default") {
        btn.classList.add("is-active");
      }
      const label = document.createElement("span");
      label.textContent = preset.name;
      btn.appendChild(label);
      btn.addEventListener("click", () => {
        if (preset.id === "default") {
          commit({ type: "default", veil: current.veil, cardVeil: current.cardVeil });
        } else {
          commit({ type: "preset", presetId: preset.id, value: preset.value, color: preset.color, veil: current.veil, cardVeil: current.cardVeil });
        }
        notify(`背景已切换：${preset.name}`);
      });
      presetList.appendChild(btn);
    }
  }

  uploadBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files && fileInput.files[0];
    fileInput.value = "";
    if (!file) return;
    try {
      const dataUrl = await readAndResize(file);
      commit({ type: "upload", value: dataUrl, veil: current.veil, cardVeil: current.cardVeil });
      notify("已应用上传的背景图片");
    } catch (error) {
      notify(error.message || "图片读取失败");
    }
  });

  urlApply.addEventListener("click", () => {
    const url = urlInput.value.trim();
    if (!url) {
      notify("请先粘贴图片 URL");
      return;
    }
    commit({ type: "url", value: url, veil: current.veil, cardVeil: current.cardVeil });
    urlInput.value = "";
    notify("已应用 URL 背景");
  });

  veilRange.addEventListener("input", () => {
    current = { ...current, veil: Number(veilRange.value) };
    apply(current);
  });
  veilRange.addEventListener("change", () => save(current));

  cardVeilRange.addEventListener("input", () => {
    current = { ...current, cardVeil: Number(cardVeilRange.value) };
    apply(current);
  });
  cardVeilRange.addEventListener("change", () => save(current));

  resetBtn.addEventListener("click", () => {
    commit({ type: "default", veil: 35 });
    veilRange.value = "35";
    cardVeilRange.value = "58";
    notify("已恢复默认背景");
  });

  renderPresets();
})();
