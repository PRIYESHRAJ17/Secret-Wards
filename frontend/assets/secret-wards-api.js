/**
 * Secret Wards (Track 3 — Knight Rebels) Frontend API Client & CanvasTexture Adapter.
 * Connects the WebGL showcase to the local Python HTTP API (proxied under /api/*)
 * and renders crisp CanvasTextures for 3D text sprites, glass shard stats, and Stage 3 quotes.
 */

const DYNAMIC_CANVAS_ITEMS = [];
let fontHookInstalled = false;

function scheduleFontRefresh(drawFn, tex) {
  DYNAMIC_CANVAS_ITEMS.push({ drawFn, tex });
  if (!fontHookInstalled && typeof document !== 'undefined' && document.fonts?.ready) {
    fontHookInstalled = true;
    document.fonts.ready.then(() => {
      for (const item of DYNAMIC_CANVAS_ITEMS) {
        try {
          item.drawFn();
          if (item.tex) item.tex.needsUpdate = true;
        } catch {
          // Ignore disposed textures
        }
      }
    });
  }
}

async function fetchJson(url, options = {}, timeoutMs = 90000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        ...(options.body ? { 'Content-Type': 'application/json' } : {}),
        ...(options.headers || {}),
      },
    });
    const data = await resp.json().catch(() => null);
    if (!resp.ok || !data || data.ok === false) {
      const msg = (data && data.error) || `Backend returned HTTP ${resp.status}`;
      return { ok: false, offline: resp.status === 502, status: resp.status, error: msg, data };
    }
    return data;
  } catch (err) {
    const isAbort = err && err.name === 'AbortError';
    return {
      ok: false,
      offline: true,
      error: isAbort
        ? 'Pipeline request timed out. Check backend server load.'
        : 'Secret Wards API server is offline. Start backend/api_server.py to run live audits.',
    };
  } finally {
    clearTimeout(timer);
  }
}

export const secretWardsApi = {
  getHealth() {
    return fetchJson('/api/health', { method: 'GET' }, 8000);
  },
  getWard(wardKey) {
    return fetchJson(`/api/wards/${encodeURIComponent(wardKey)}`, { method: 'GET' }, 10000);
  },
  sanitizeSnippet({ text, filename = 'ward_note.txt' }) {
    return fetchJson('/api/sanitize-snippet', {
      method: 'POST',
      body: JSON.stringify({ text, filename }),
    }, 30000);
  },
  runPipeline({ mode = 'dev', ward = null, files = null, includeScore = true } = {}) {
    return fetchJson('/api/pipeline/run', {
      method: 'POST',
      body: JSON.stringify({ mode, ward, files, include_score: includeScore }),
    }, 120000);
  },
  getBundleUrl(runId) {
    return `/api/outputs/${encodeURIComponent(runId)}/bundle.zip`;
  },
  getReportUrl(runId) {
    return `/api/outputs/${encodeURIComponent(runId)}/report.json`;
  },
};

function makeCanvasTexture(THREE, width, height, drawFn, { mipmaps = true } = {}) {
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  const runDraw = () => drawFn(ctx, width, height);
  runDraw();

  const tex = new THREE.CanvasTexture(canvas);
  if (THREE.SRGBColorSpace) tex.colorSpace = THREE.SRGBColorSpace;
  tex.generateMipmaps = mipmaps;
  if (!mipmaps) {
    tex.minFilter = THREE.LinearFilter;
    tex.magFilter = THREE.LinearFilter;
  }
  tex.anisotropy = 4;
  tex.needsUpdate = true;
  scheduleFontRefresh(runDraw, tex);
  return tex;
}

/**
 * Draw editorial typography matching Stage 1-4 styling.
 * Spec: { width, height, parts: [{ text, x, y, font, size, color, gradient, align, baseline, upper }], shadow }
 */
export function createStageTextSprite(THREE, cfg) {
  const {
    width,
    height,
    parts,
    baseScale = 0.25,
    anchor = 'center-center',
    appearAt = 0,
    disappearAt = 1,
    appearDuration,
    shadow = null,
    tone = 'sage',
  } = cfg;

  const tex = makeCanvasTexture(THREE, width, height, (ctx, w, h) => {
    ctx.clearRect(0, 0, w, h);
    if (shadow) {
      ctx.shadowColor = shadow.color || 'rgba(0,0,0,0.22)';
      ctx.shadowBlur = shadow.blur ?? 14;
      ctx.shadowOffsetY = shadow.y ?? 3;
    } else {
      ctx.shadowColor = 'transparent';
      ctx.shadowBlur = 0;
    }
    for (const part of parts) {
      const text = part.upper ? part.text.toUpperCase() : part.text;
      const weight = part.weight || 400;
      const style = part.italic ? 'italic ' : '';
      const family = part.family || "'STK Bureau Serif', 'Newsreader', Georgia, serif";
      ctx.font = `${style}${weight} ${part.size}px ${family}`;
      ctx.textAlign = part.align || 'center';
      ctx.textBaseline = part.baseline || 'alphabetic';

      if (part.gradient || tone === 'tealGrad') {
        const grad = ctx.createLinearGradient(0, 0, w, h);
        if (tone === 'stage3') {
          grad.addColorStop(0, '#c8eadb');
          grad.addColorStop(0.55, '#ffffff');
          grad.addColorStop(1, '#bfe5d4');
        } else {
          grad.addColorStop(0, '#1e5b53');
          grad.addColorStop(0.5, '#3b8c80');
          grad.addColorStop(1, '#1a524b');
        }
        ctx.fillStyle = grad;
      } else {
        ctx.fillStyle = part.color || (tone === 'white' ? '#ffffff' : '#35665d');
      }
      ctx.fillText(text, part.x * w, part.y * h);
    }
  });

  const out = {
    texture: tex,
    atlasUV: { offset: [0, 0], scale: [1, 1] },
    aspect: width / height,
    rotate: false,
    baseScale,
    anchor,
    appearAt,
    disappearAt,
  };
  if (appearDuration !== undefined) out.appearDuration = appearDuration;
  return out;
}

export function buildStage1TextItems(THREE) {
  return [
    createStageTextSprite(THREE, {
      width: 1024,
      height: 460,
      baseScale: 0.4,
      anchor: 'center-center',
      appearAt: 0,
      disappearAt: 0.02,
      tone: 'tealGrad',
      parts: [
        { text: 'They', x: 0.59, y: 0.36, size: 132, family: "'STK Bureau Serif', Georgia, serif", align: 'center' },
        { text: 'Merged', x: 0.48, y: 0.78, size: 204, family: "'Bethany Elingston', 'Newsreader', serif", align: 'center' },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 900,
      height: 400,
      baseScale: 0.25,
      anchor: 'top-left',
      appearAt: 0.2,
      disappearAt: 0.6,
      tone: 'tealGrad',
      parts: [
        { text: 'Every', x: 0.38, y: 0.42, size: 156, family: "'Bethany Elingston', 'Newsreader', serif" },
        { text: 'Ward', x: 0.55, y: 0.77, size: 118, family: "'STK Bureau Serif', Georgia, serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 680,
      height: 290,
      baseScale: 0.17,
      anchor: 'bottom-right',
      appearAt: 0.3,
      disappearAt: 0.6,
      tone: 'tealGrad',
      parts: [
        { text: 'kept', x: 0.64, y: 0.38, size: 84, family: "'STK Bureau Serif', Georgia, serif" },
        { text: 'Records', x: 0.48, y: 0.80, size: 114, family: "'STK Bureau Serif', Georgia, serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 720,
      height: 360,
      baseScale: 0.175,
      anchor: 'center-center',
      appearAt: 0.6,
      disappearAt: 0.95,
      tone: 'tealGrad',
      parts: [
        { text: 'on', x: 0.22, y: 0.56, size: 144, family: "'Bethany Elingston', 'Newsreader', serif" },
        { text: 'FILE', x: 0.61, y: 0.68, size: 146, family: "'STK Bureau Serif', Georgia, serif" },
      ],
    }),
  ];
}

export function buildGate1to2TextItems(THREE) {
  return [
    createStageTextSprite(THREE, {
      width: 512,
      height: 280,
      baseScale: 0.15,
      anchor: 'center-center',
      appearAt: 1,
      disappearAt: 2,
      tone: 'white',
      shadow: { color: 'rgba(0,0,0,0.35)', blur: 18 },
      parts: [
        { text: 'Yet,', x: 0.5, y: 0.68, size: 175, family: "'Bethany Elingston', 'Newsreader', serif" },
      ],
    }),
  ];
}

export function buildStage2HeroTextItems(THREE) {
  return [
    createStageTextSprite(THREE, {
      width: 1120,
      height: 440,
      baseScale: 0.4,
      anchor: 'center-center',
      appearAt: 0,
      disappearAt: 0.2,
      tone: 'white',
      shadow: { color: 'rgba(40,0,0,0.4)', blur: 20 },
      parts: [
        { text: 'Every', x: 0.3, y: 0.28, size: 116, family: "'Bethany Elingston', 'Newsreader', serif" },
        { text: 'File Leaks', x: 0.5, y: 0.78, size: 172, family: "'STK Bureau Serif', Georgia, serif" },
      ],
    }),
  ];
}

export function buildStage3TextItems(THREE) {
  return [
    createStageTextSprite(THREE, {
      width: 760,
      height: 300,
      baseScale: 0.25,
      anchor: 'bottom-left',
      appearAt: 0.05,
      disappearAt: 0.3,
      tone: 'stage3',
      parts: [
        { text: 'Filters', x: 0.44, y: 0.42, size: 108, family: "'Bethany Elingston', serif" },
        { text: 'scrub', x: 0.52, y: 0.78, size: 88, family: "'STK Bureau Serif', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 900,
      height: 420,
      baseScale: 0.4,
      anchor: 'center-center',
      appearAt: 0.3,
      disappearAt: 0.4,
      tone: 'stage3',
      parts: [
        { text: 'Strings', x: 0.5, y: 0.72, size: 224, family: "'Bethany Elingston', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 780,
      height: 300,
      baseScale: 0.25,
      anchor: 'top-left',
      appearAt: 0.4,
      disappearAt: 0.6,
      tone: 'stage3',
      parts: [
        { text: 'yet', x: 0.34, y: 0.38, size: 82, family: "'STK Bureau Serif', serif" },
        { text: 'Attackers', x: 0.52, y: 0.80, size: 112, family: "'Bethany Elingston', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 820,
      height: 300,
      baseScale: 0.25,
      anchor: 'bottom-right',
      appearAt: 0.5,
      disappearAt: 0.6,
      tone: 'stage3',
      parts: [
        { text: 'crack', x: 0.38, y: 0.40, size: 84, family: "'STK Bureau Serif', serif" },
        { text: 'Every', x: 0.54, y: 0.80, size: 122, family: "'Bethany Elingston', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 840,
      height: 360,
      baseScale: 0.25,
      anchor: 'center-center',
      appearAt: 0.6,
      disappearAt: 0.7,
      tone: 'stage3',
      parts: [
        { text: 'unmasked', x: 0.48, y: 0.42, size: 96, family: "'STK Bureau Serif', serif" },
        { text: 'clue & link', x: 0.5, y: 0.80, size: 108, family: "'Bethany Elingston', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 860,
      height: 400,
      baseScale: 0.38,
      anchor: 'center-center',
      appearAt: 0.7,
      disappearAt: 0.8,
      tone: 'stage3',
      parts: [
        { text: 'Trail', x: 0.5, y: 0.74, size: 230, family: "'Bethany Elingston', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 960,
      height: 340,
      baseScale: 0.38,
      anchor: 'center-center',
      appearAt: 0.8,
      disappearAt: 0.87,
      tone: 'stage3',
      parts: [
        { text: 'close the Gap', x: 0.5, y: 0.68, size: 146, family: "'STK Bureau Serif', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 760,
      height: 360,
      baseScale: 0.25,
      anchor: 'top-left',
      appearAt: 0.87,
      disappearAt: 0.99,
      tone: 'stage3',
      parts: [
        { text: 'and that’s', x: 0.48, y: 0.36, size: 80, family: "'STK Bureau Serif', serif" },
        { text: 'Why', x: 0.5, y: 0.82, size: 162, family: "'Bethany Elingston', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 800,
      height: 380,
      baseScale: 0.25,
      anchor: 'bottom-right',
      appearAt: 0.93,
      disappearAt: 0.99,
      tone: 'stage3',
      parts: [
        { text: 'we built the', x: 0.45, y: 0.36, size: 78, family: "'STK Bureau Serif', serif" },
        { text: 'Firewall', x: 0.5, y: 0.82, size: 160, family: "'Bethany Elingston', serif" },
      ],
    }),
  ];
}

export function buildStage4TextItems(THREE, textsAtlasTex, Nv, Pv) {
  const weights = [1, 2, 1, 1, 1, 1, 1, 1];
  const totalW = weights.reduce((a, b) => a + b, 0);
  const span = 0.9;
  let acc = 0;
  const windows = weights.map((w) => {
    const start = (acc / totalW) * span;
    acc += w;
    return [start, (acc / totalW) * span];
  });

  // Index 1 strictly preserves original 'zero' blue logo artwork from texts.ktx2
  return [
    createStageTextSprite(THREE, {
      width: 920,
      height: 260,
      baseScale: 0.35,
      anchor: 'center-center',
      appearAt: windows[0][0],
      disappearAt: windows[0][1],
      tone: 'tealGrad',
      parts: [
        { text: 'Introducing,', x: 0.5, y: 0.68, size: 152, family: "'Bethany Elingston', serif" },
      ],
    }),
    {
      texture: textsAtlasTex,
      atlasUV: Nv(1083.94, 1769.27, 963.5, 278.73),
      aspect: Pv(963.5, 278.73),
      baseScale: 0.35,
      anchor: 'center-center',
      appearAt: windows[1][0],
      disappearAt: windows[1][1],
    },
    createStageTextSprite(THREE, {
      width: 960,
      height: 440,
      baseScale: 0.35,
      anchor: 'center-center',
      appearAt: windows[2][0],
      disappearAt: windows[2][1],
      tone: 'tealGrad',
      parts: [
        { text: 'where PRIVACY', x: 0.5, y: 0.40, size: 108, family: "'STK Bureau Serif', serif" },
        { text: 'becomes Real', x: 0.5, y: 0.80, size: 146, family: "'Bethany Elingston', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 1040,
      height: 420,
      baseScale: 0.35,
      anchor: 'center-center',
      appearAt: windows[3][0],
      disappearAt: windows[3][1],
      tone: 'tealGrad',
      parts: [
        { text: 'Real records', x: 0.5, y: 0.42, size: 128, family: "'Bethany Elingston', serif" },
        { text: 'across 4 hospitals', x: 0.5, y: 0.78, size: 92, family: "'STK Bureau Serif', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 1040,
      height: 420,
      baseScale: 0.35,
      anchor: 'center-center',
      appearAt: windows[4][0],
      disappearAt: windows[4][1],
      tone: 'tealGrad',
      parts: [
        { text: 'Real scrubbing', x: 0.5, y: 0.42, size: 126, family: "'Bethany Elingston', serif" },
        { text: 'preserving every vital', x: 0.5, y: 0.78, size: 84, family: "'STK Bureau Serif', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 1080,
      height: 420,
      baseScale: 0.35,
      anchor: 'center-center',
      appearAt: windows[5][0],
      disappearAt: windows[5][1],
      tone: 'tealGrad',
      parts: [
        { text: 'Real defense', x: 0.5, y: 0.42, size: 128, family: "'Bethany Elingston', serif" },
        { text: 'against linkage attacks', x: 0.5, y: 0.78, size: 82, family: "'STK Bureau Serif', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 960,
      height: 280,
      baseScale: 0.35,
      anchor: 'center-center',
      appearAt: windows[6][0],
      disappearAt: windows[6][1],
      tone: 'tealGrad',
      parts: [
        { text: 'BUILT offline with', x: 0.5, y: 0.66, size: 108, family: "'STK Bureau Serif', serif" },
      ],
    }),
    createStageTextSprite(THREE, {
      width: 1080,
      height: 380,
      baseScale: 0.35,
      anchor: 'center-center',
      appearAt: windows[7][0],
      disappearAt: windows[7][1],
      tone: 'tealGrad',
      parts: [
        { text: 'CPU-only HKDF &', x: 0.5, y: 0.38, size: 106, family: "'STK Bureau Serif', serif" },
        { text: 'Privacy Architecture', x: 0.5, y: 0.80, size: 124, family: "'Bethany Elingston', serif" },
      ],
    }),
  ];
}

function wrapText(ctx, text, x, y, maxWidth, lineHeight) {
  const words = text.split(/\s+/);
  let line = '';
  let curY = y;
  for (const word of words) {
    const test = line ? `${line} ${word}` : word;
    if (ctx.measureText(test).width > maxWidth && line) {
      ctx.fillText(line, x, curY);
      line = word;
      curY += lineHeight;
    } else {
      line = test;
    }
  }
  if (line) ctx.fillText(line, x, curY);
}

/**
 * Generates a 2048x2048 atlas matching exact Stage 2 glass shard rectangles in Gb().
 */
export function createShardsOverlayAtlas(THREE) {
  const regions = [
    { x: 0, y: 0, w: 856, h: 381, stat: '84.1%', sub: 'PII leaked by starter baseline', foot: '2,718 of 3,230 items' },
    { x: 881, y: 0, w: 860, h: 518, stat: '100%', sub: 'canaries exposed in', foot: 'Filenames & headers' },
    { x: 1765, y: 0, w: 735, h: 283, rot: true, stat: '0-LLM', sub: 'CPU-only, offline, <=50M params', foot: '15 min max / 4 GB RAM' },
    { x: 0, y: 699, w: 1024, h: 363, stat: '48', sub: 'Patients linked across 4 hospitals', foot: '200 multi-format ward files' },
    { x: 1042, y: 737, w: 952, h: 502, stat: '4/4', sub: 'Bilingual canary traps leaked', foot: 'English, Hindi & Hinglish' },
    { x: 563, y: 1073, w: 975, h: 370, rot: true, stat: '7/7', sub: 'Side-channel audit vectors checked', foot: 'Base64, EXIF, keys & filenames' },
  ];

  return makeCanvasTexture(THREE, 2048, 2048, (ctx) => {
    ctx.clearRect(0, 0, 2048, 2048);
    ctx.fillStyle = '#ffffff';
    ctx.shadowColor = 'rgba(0,0,0,0.45)';
    ctx.shadowBlur = 10;

    for (const r of regions) {
      ctx.save();
      if (r.rot) {
        // Inverse of Ub's rot:true UV transform: rotate +90deg inside (r.x..r.x+r.h, r.y..r.y+r.w)
        ctx.translate(r.x + r.h, r.y);
        ctx.rotate(Math.PI / 2);
      } else {
        ctx.translate(r.x, r.y);
      }

      const w = r.w;
      const h = r.h;
      ctx.textBaseline = 'top';
      ctx.textAlign = 'left';

      let statSize = Math.round(h * 0.40);
      ctx.font = `400 ${statSize}px 'STK Bureau Serif', Georgia, serif`;
      let statWidth = ctx.measureText(r.stat).width;
      const maxStatW = w * 0.42;
      if (statWidth > maxStatW) {
        statSize = Math.max(28, Math.floor(statSize * (maxStatW / statWidth)));
        ctx.font = `400 ${statSize}px 'STK Bureau Serif', Georgia, serif`;
        statWidth = ctx.measureText(r.stat).width;
      }
      ctx.fillText(r.stat, 24, 20);

      const textX = Math.max(24 + statWidth + 24, w * 0.46);
      ctx.font = `400 ${Math.round(h * 0.13)}px 'Inter', sans-serif`;
      wrapText(ctx, r.sub, textX, 28, Math.max(160, w - textX - 24), Math.round(h * 0.165));

      ctx.font = `400 ${Math.round(h * 0.155)}px 'Bethany Elingston', Georgia, serif`;
      ctx.fillText(r.foot, 28, h * 0.67);

      ctx.restore();
    }
  });
}

/**
 * Generates a 2048x2048 atlas matching exact Stage 3 floating quote rectangles in nS().
 */
export function createQuoteShredsAtlas(THREE) {
  const quotes = [
    {
      x: 0, y: 0, w: 492, h: 912,
      quote: '“One patient appears as Ram Kumar in Sanjeevani IPD and Shri Ram in District HQ. Only deterministic HMAC pseudonym linkage binds both journeys.”',
      author: 'Trap 1 · Identity Resolution',
    },
    {
      x: 492, y: 0, w: 492, h: 912,
      quote: '“Naïve regex erases Ward No. 4 and Azithromycin 500mg along with phone numbers. Contextual arbitration keeps 100% of clinical probes intact.”',
      author: 'Trap 2 · Clinical Utility',
    },
    {
      x: 982, y: 0, w: 492, h: 912,
      quote: '“Indian hospital records mix English, Devanagari kinship tags, and Hinglish shorthand like umar 42 within a single discharge summary.”',
      author: 'Trap 3 · Multilingual PII',
    },
    {
      x: 0, y: 911, w: 491, h: 1137,
      quote: '“Constant global date shifts leak intervals via birthday queries. Per-patient HKDF date shifting preserves true length-of-stay deltas safely.”',
      author: 'Trap 4 · Longitudinal Dates',
    },
    {
      x: 492, y: 913, w: 490, h: 1135,
      quote: '“Scanning only message bodies misses Aadhaar inside CSV headers, JSON keys, base64 metadata, and patient names inside filenames.”',
      author: 'Trap 5 · 7-Channel Hygiene',
    },
    {
      x: 983, y: 912, w: 491, h: 911,
      quote: '“Corrupt binary blobs fail closed into quarantine instead of silently passing raw PII, while 4 of 4 canary tokens remain sealed offline.”',
      author: 'Trap 6 · Quarantine & Audit',
    },
  ];

  return makeCanvasTexture(THREE, 2048, 2048, (ctx) => {
    ctx.clearRect(0, 0, 2048, 2048);
    ctx.shadowColor = 'transparent';

    for (const q of quotes) {
      ctx.save();
      ctx.fillStyle = '#ddece2';
      ctx.fillRect(q.x + 8, q.y + 8, q.w - 16, q.h - 16);

      ctx.strokeStyle = 'rgba(38, 74, 52, 0.35)';
      ctx.lineWidth = 3;
      ctx.strokeRect(q.x + 18, q.y + 18, q.w - 36, q.h - 36);

      ctx.fillStyle = '#1b3826';
      ctx.font = `700 22px 'PP Supply Mono', 'Supply Sans', monospace`;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText('SECRET WARDS // TRACK 3', q.x + 34, q.y + 38);

      ctx.strokeStyle = 'rgba(27, 56, 38, 0.25)';
      ctx.beginPath();
      ctx.moveTo(q.x + 34, q.y + 76);
      ctx.lineTo(q.x + q.w - 34, q.y + 76);
      ctx.stroke();

      ctx.fillStyle = '#152b1d';
      ctx.font = `400 32px 'STK Bureau Serif', Georgia, serif`;
      wrapText(ctx, q.quote, q.x + 34, q.y + 108, q.w - 68, 44);

      ctx.fillStyle = '#2d5a3f';
      ctx.font = `400 24px 'PP Supply Mono', monospace`;
      ctx.fillText(q.author, q.x + 34, q.y + q.h - 72);
      ctx.restore();
    }
  });
}

/**
 * Generates a 2048x2048 atlas matching exact Stage 3 floating sheet rectangles in eS().
 */
export function createCertSheetsAtlas(THREE) {
  const boxes = [
    [0, 0, 658, 512, 'SANJEEVANI IPD DISCHARGE', 'Patient: PSN-8A4C9F12D0', 'Age Band: 40-44 | PIN: 226xxx', 'Dx: Acute Dengue | Plt 68,000'],
    [658, 0, 658, 512, 'AROGYA LEGACY EXPORT', 'Rows Preserved: Schema Locked', 'Aadhaar: [REDACT] | DOB: 1984', 'Vitals & Rx Retained: 100%'],
    [1316, 0, 658, 512, 'JEEVAN JYOTI WARD TSV', 'PSN Linked: 48 Patients / 4 Sites', 'Date Shift: Per-Key +42..341d', 'Canary Check: 0 / 4 Leaked'],
    [0, 512, 658, 512, 'DHH FHIR R4 BUNDLE', 'Resource: Patient / Encounter', 'MRN / ABHA: HKDF Pseudonym', 'JSON Depth & Structure: Valid'],
    [0, 1024, 658, 512, '7-CHANNEL HYGIENE SCAN', 'Body + Filenames + Headers', 'Keys + Metadata + Base64', 'Secret Exposure: Zero'],
    [0, 1536, 658, 512, 'QUARANTINE GATEKEEPER', 'Corrupt & Over-Limit Inputs', 'Fail-Closed Isolation Active', 'Silent Drops: 0 Recorded'],
    [658, 1536, 658, 512, 'HKDF KEY ISOLATION', 'Domain: pseudonym | dateshift', 'Domain: filename | CPU-Only', 'Zero LLM / Zero Network'],
    [1316, 1536, 658, 512, 'CONTRACT VERIFICATION', 'Schema: raksha-report/1', 'Exports: sanitized/ + jsonl', 'Status: CONTRACT OK'],
  ];

  return makeCanvasTexture(THREE, 2048, 2048, (ctx) => {
    ctx.clearRect(0, 0, 2048, 2048);
    ctx.shadowColor = 'transparent';
    for (const [x, y, w, h, title, l1, l2, l3] of boxes) {
      ctx.fillStyle = '#f3eee4';
      ctx.fillRect(x + 10, y + 10, w - 20, h - 20);
      ctx.strokeStyle = '#73917f';
      ctx.lineWidth = 4;
      ctx.strokeRect(x + 24, y + 24, w - 48, h - 48);

      ctx.fillStyle = '#1f3a2c';
      ctx.font = `700 26px 'PP Supply Mono', monospace`;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      ctx.fillText(title, x + 48, y + 54);

      ctx.fillStyle = '#335943';
      ctx.fillRect(x + 48, y + 96, w - 96, 3);

      ctx.fillStyle = '#1b1d1c';
      ctx.font = `400 28px 'STK Bureau Serif', Georgia, serif`;
      ctx.fillText(l1, x + 48, y + 128);
      ctx.fillText(l2, x + 48, y + 188);
      ctx.fillText(l3, x + 48, y + 248);

      ctx.fillStyle = '#2d7a4f';
      ctx.font = `700 22px 'PP Supply Mono', monospace`;
      ctx.fillText('VERIFIED BY SECRET WARDS', x + 48, y + h - 84);
    }
  });
}

export function saveLastAuditResult(result) {
  try {
    sessionStorage.setItem('secretWards:lastAudit', JSON.stringify(result));
  } catch {
    // ignore storage limits
  }
}

export function loadLastAuditResult() {
  try {
    const raw = sessionStorage.getItem('secretWards:lastAudit');
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
