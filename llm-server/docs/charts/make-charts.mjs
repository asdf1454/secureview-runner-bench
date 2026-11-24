// docs/PROGRESS.md의 그래프를 만든다. 값은 docs/eval/의 평가 기록과 CHANGELOG.md에서 옮겼다.
// 실행: node docs/charts/make-charts.mjs
import { writeFileSync } from "node:fs";

const dir = new URL("./", import.meta.url);
const FONT = 'system-ui, -apple-system, "Segoe UI", "Malgun Gothic", sans-serif';
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;");

function save(name, w, h, title, note, body) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" role="img" aria-label="${esc(title)}">
<title>${esc(title)}</title>
<style>
svg{--surface:#fcfcfb;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--s1:#2a78d6;--s2:#eb6834}
@media (prefers-color-scheme:dark){svg{--surface:#1a1a19;--ink:#f0efec;--ink2:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--s1:#3987e5;--s2:#d95926}}
text{font-family:${FONT};font-size:12px;fill:var(--ink2)}
.t{font-size:15px;font-weight:600;fill:var(--ink)}.n{fill:var(--muted)}.v{fill:var(--ink);font-weight:600}.tick{font-variant-numeric:tabular-nums;fill:var(--muted)}
</style>
<rect width="${w}" height="${h}" fill="var(--surface)"/>
<text class="t" x="20" y="28">${esc(title)}</text>
<text class="n" x="20" y="47">${esc(note)}</text>
${body}
</svg>
`;
  writeFileSync(new URL(name, dir), svg);
}

const txt = (x, y, s, cls = "", anchor = "start") =>
  `<text x="${x}" y="${y}" text-anchor="${anchor}"${cls ? ` class="${cls}"` : ""}>${esc(s)}</text>`;
const hline = (x1, x2, y, c = "--grid") => `<line x1="${x1}" x2="${x2}" y1="${y}" y2="${y}" stroke="var(${c})"/>`;

function yGrid(box, max, ticks, unit = "") {
  const y = (v) => box.b - (v / max) * (box.b - box.t);
  const body = ticks.map((v) => hline(box.l, box.r, y(v), v === 0 ? "--axis" : "--grid") + txt(box.l - 8, y(v) + 4, v + unit, "tick", "end")).join("");
  return { y, body };
}

function legend(x, y, items) {
  let cx = x;
  return items.map(([label, color]) => {
    const out = `<rect x="${cx}" y="${y - 9}" width="10" height="10" rx="2" fill="var(${color})"/>` + txt(cx + 15, y, label);
    cx += 15 + label.length * 12 + 18;
    return out;
  }).join("");
}

function line(xs, ys, values, color, labelOf) {
  const pts = values.map((v, i) => `${xs[i]},${ys(v)}`).join(" ");
  const dots = values.map((v, i) =>
    `<circle cx="${xs[i]}" cy="${ys(v)}" r="4.5" fill="var(${color})" stroke="var(--surface)" stroke-width="2"><title>${esc(labelOf(i))}</title></circle>`).join("");
  return `<polyline points="${pts}" fill="none" stroke="var(${color})" stroke-width="2" stroke-linejoin="round"/>${dots}`;
}

// 위쪽만 둥근 세로 막대
function vbar(x, w, base, top, color, tip) {
  if (base - top < 1) return "";
  const r = Math.min(4, base - top);
  return `<path d="M${x},${base}V${top + r}Q${x},${top} ${x + r},${top}H${x + w - r}Q${x + w},${top} ${x + w},${top + r}V${base}Z" fill="var(${color})"><title>${esc(tip)}</title></path>`;
}

// 오른쪽만 둥근 가로 막대
function hbar(x, y, len, h, color, tip) {
  if (len < 1) return "";
  const r = Math.min(4, len);
  return `<path d="M${x},${y}H${x + len - r}Q${x + len},${y} ${x + len},${y + r}V${y + h - r}Q${x + len},${y + h} ${x + len - r},${y + h}H${x}Z" fill="var(${color})"><title>${esc(tip)}</title></path>`;
}

// 1. 테스트 수
{
  const v = ["v0.1", "v0.2", "v0.3", "v0.4", "v0.5", "v0.6", "v0.7", "v0.8", "v0.9", "v1.0.0", "v1.0.3", "v1.1.0", "v1.1.2"];
  const n = [12, 20, 45, 51, 57, 65, 72, 76, 78, 88, 104, 135, 138];
  const box = { l: 56, r: 640, t: 72, b: 270 };
  const g = yGrid(box, 150, [0, 50, 100, 150]);
  const xs = v.map((_, i) => box.l + 18 + (i * (box.r - box.l - 50)) / (v.length - 1));
  save("tests-by-version.svg", 680, 305, "버전별 자동 테스트 수", "모든 테스트 통과 기준", g.body +
    line(xs, g.y, n, "--s1", (i) => `${v[i]}: ${n[i]}개`) +
    v.map((s, i) => txt(xs[i], box.b + 20, s, "tick", "middle")).join("") +
    txt(xs[0], g.y(n[0]) - 12, "12개", "v", "middle") + txt(xs[12], g.y(n[12]) - 12, "138개", "v", "middle"));
}

// 2. 품질
{
  const v = ["v0.6.0 (45건)", "v0.7.0", "v0.8.0", "v1.0.3", "v1.1.0", "v1.1.2"];
  const fp = [52.4, 65.2, 56.5, 56.5, 52.2, 52.2];
  const rc = [95.8, 100, 100, 100, 100, 100];
  const box = { l: 56, r: 530, t: 86, b: 300 };
  const g = yGrid(box, 100, [0, 25, 50, 75, 100], "%");
  const xs = v.map((_, i) => box.l + 55 + (i * (box.r - box.l - 110)) / 5);
  save("quality-by-version.svg", 680, 335, "버전별 오탐 감소율과 재현율", "직접 만든 예제 48건 기준 (v0.6.0만 45건), 공식 평가 아님", g.body +
    legend(20, 70, [["오탐 감소율", "--s1"], ["재현율", "--s2"]]) +
    `<line x1="${box.l}" x2="${box.r}" y1="${g.y(30)}" y2="${g.y(30)}" stroke="var(--muted)"/>` + txt(box.r + 8, g.y(30) + 4, "오탐 감소 목표 30%", "n") +
    line(xs, g.y, fp, "--s1", (i) => `${v[i]} 오탐 감소 ${fp[i]}%`) +
    line(xs, g.y, rc, "--s2", (i) => `${v[i]} 재현율 ${rc[i]}%`) +
    v.map((s, i) => txt(xs[i], box.b + 20, s, "tick", "middle")).join("") +
    txt(xs[0], g.y(fp[0]) + 22, "52%", "v", "middle") + txt(xs[1], g.y(fp[1]) - 12, "65%", "v", "middle") + txt(xs[3], g.y(fp[3]) - 12, "57%", "v", "middle") + txt(xs[5], g.y(fp[5]) + 22, "52%", "v", "middle") +
    txt(xs[0], g.y(rc[0]) + 22, "96%", "v", "middle") + txt(xs[5], g.y(rc[5]) - 12, "100%", "v", "middle"));
}

// 3. 판정 불가와 놓친 취약점
{
  const v = ["v0.6.0", "v0.7.0", "v0.8.0", "v1.0.3", "v1.1.0", "v1.1.2"];
  const un = [1, 14, 1, 1, 0, 0];
  const miss = [1, 0, 0, 0, 0, 0];
  const box = { l: 56, r: 640, t: 86, b: 280 };
  const g = yGrid(box, 16, [0, 4, 8, 12, 16]);
  const W = 22;
  const bars = v.map((s, i) => {
    const c = box.l + ((i + 0.5) * (box.r - box.l)) / 6;
    const a = c - W - 1, b = c + 1;
    return vbar(a, W, box.b, g.y(un[i]), "--s1", `${s} 판정 불가 ${un[i]}건`) + vbar(b, W, box.b, g.y(miss[i]), "--s2", `${s} 놓친 취약점 ${miss[i]}건`) +
      txt(a + W / 2, g.y(un[i]) - 6, un[i], "v", "middle") + txt(b + W / 2, g.y(miss[i]) - 6, miss[i], "v", "middle") +
      txt(c, box.b + 20, s, "tick", "middle");
  }).join("");
  save("failures-by-version.svg", 680, 315, "버전별 판정 불가와 놓친 취약점", "v0.7.0은 놓친 취약점을 없앴지만 판정 불가가 늘었고, v0.8.0에서 해소", g.body +
    legend(20, 70, [["판정 불가", "--s1"], ["놓친 취약점", "--s2"]]) + bars);
}

// 가로 막대 공통
function hbars(name, title, note, rows, max, unitOf) {
  const l = 190, r = 590, top = 66, rowH = 30, barH = 16;
  const h = top + rows.length * rowH + 16;
  const body = rows.map(([label, value, tip], i) => {
    const y = top + i * rowH;
    const len = (value / max) * (r - l);
    return txt(l - 10, y + 13, label, "", "end") + hbar(l, y, len, barH, "--s1", tip || `${label}: ${unitOf(value, i)}`) +
      txt(l + len + 8, y + 13, unitOf(value, i), "v");
  }).join("") + `<line x1="${l}" x2="${l}" y1="${top - 6}" y2="${h - 18}" stroke="var(--axis)"/>`;
  save(name, 680, h, title, note, body);
}

// 4. 단계별 시간
hbars("time-by-step.svg", "단계별 처리 시간 (v1.1.2)", "RTX 2050 4GB 기준 건당 중앙값. 수정안과 질의응답은 v1.0.3 측정값", [
  ["진짜 취약점 1건 (판정+설명)", 19.1], ["모델 올리기 (시작 때 1회)", 18], ["수정안 1건", 12.1], ["판정 1건 (500줄 측정 평균)", 7.6], ["질의응답 1건 (4회 중앙값)", 3.7],
], 30, (v) => `${v}초`);

// 5. CWE별 오탐 감소
const cwe = [["CWE-22 경로 조작", 2, 2], ["CWE-79 XSS", 2, 2], ["CWE-89 SQL 인젝션", 4, 5], ["CWE-78 명령어 삽입", 2, 2], ["CWE-120 버퍼 오버플로", 0, 2],
  ["CWE-134 포맷 스트링", 1, 2], ["CWE-190 정수 오버플로", 1, 2], ["CWE-416 해제 후 사용", 0, 2], ["CWE-476 널 역참조", 0, 2], ["CWE-798 하드코딩 비밀", 0, 2]];
hbars("false-positive-by-cwe.svg", "CWE별 오탐 감소 (v1.1.2)", "안전한 코드 중 오탐으로 걸러 낸 비율. CWE당 2~5건이라 참고용", cwe.map(([n, a, b]) => [n, (a / b) * 100]), 100,
  (v, i) => `${cwe[i][1]}/${cwe[i][2]}건`);

// 6. 모델 비교
{
  const box = { l: 64, r: 620, t: 84, b: 294 };
  const g = yGrid(box, 8, [0, 2, 4, 6, 8]);
  const x = (s) => box.l + (s / 50) * (box.r - box.l);
  const m = [["qwen2.5-coder:7b (선택)", 34.1, 7, -12], ["qwen2.5-coder:3b", 6.1, 5, -12], ["exaone3.5:7.8b", 45.6, 4, -12]];
  const dots = m.map(([n, s, a, dy]) =>
    `<circle cx="${x(s)}" cy="${g.y(a)}" r="6" fill="var(--s1)" stroke="var(--surface)" stroke-width="2"><title>${esc(`${n}: ${a}/8, ${s}초`)}</title></circle>` +
    txt(x(s), g.y(a) + dy, n, "v", "middle")).join("");
  const xt = [0, 10, 20, 30, 40, 50].map((s) => txt(x(s), box.b + 20, `${s}초`, "tick", "middle")).join("");
  save("model-comparison.svg", 680, 350, "모델 비교: 정답 수와 판정 시간", "v0.2.0 프롬프트 기준, 예제 8건. 왼쪽 위일수록 좋음", g.body + dots + xt +
    txt((box.l + box.r) / 2, box.b + 42, "판정 1건 중앙값", "n", "middle") + txt(20, 70, "정답 수 (8건 중)", "n"));
}
