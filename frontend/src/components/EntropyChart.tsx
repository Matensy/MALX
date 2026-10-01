/** Entropy across the file (0–8 bits/byte). Values above 7.2 look compressed/encrypted. */
export default function EntropyChart({ values, height = 120 }: { values: number[]; height?: number }) {
  if (!values.length) return <div className="text-[12px] text-muted">No entropy profile.</div>;
  const w = 600;
  const h = height;
  const pad = 22;
  const x = (i: number) => pad + (i / Math.max(1, values.length - 1)) * (w - pad - 6);
  const y = (v: number) => 6 + (1 - v / 8) * (h - 6 - 16);
  const path = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = `${path} L${x(values.length - 1)},${y(0)} L${x(0)},${y(0)} Z`;
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full" preserveAspectRatio="none" role="img" aria-label="Entropy profile">
      <defs>
        <linearGradient id="ent" x1="0" x2="0" y1="0" y2="1">
          <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.45" />
          <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {[0, 2, 4, 6, 8].map((v) => (
        <g key={v}>
          <line x1={pad} x2={w - 6} y1={y(v)} y2={y(v)} stroke="#1d2a3a" strokeWidth="1" />
          <text x={2} y={y(v) + 3} fill="#56687c" fontSize="9">{v}</text>
        </g>
      ))}
      <line x1={pad} x2={w - 6} y1={y(7.2)} y2={y(7.2)} stroke="#f43f5e" strokeDasharray="4 4" strokeWidth="1" opacity="0.7" />
      <text x={w - 120} y={y(7.2) - 3} fill="#f43f5e" fontSize="9" opacity="0.8">7.2 packed/encrypted-like</text>
      <path d={area} fill="url(#ent)" />
      <path d={path} fill="none" stroke="#38bdf8" strokeWidth="1.5" />
      <text x={pad} y={h - 2} fill="#56687c" fontSize="9">start of file</text>
      <text x={w - 50} y={h - 2} fill="#56687c" fontSize="9">end</text>
    </svg>
  );
}
