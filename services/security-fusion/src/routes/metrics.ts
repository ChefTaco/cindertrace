const values = new Map<string, number>();
export function incMetric(name: string, amount = 1): void {
  values.set(name, (values.get(name) ?? 0) + amount);
}
export function setMetricGauge(name: string, value: number): void {
  values.set(name, value);
}
export function renderMetrics(): string {
  return (
    [...values]
      .map(
        ([k, v]) =>
          `security_fusion_${k.replace(/[A-Z]/g, (x) => "_" + x.toLowerCase())} ${v}`,
      )
      .join("\n") + "\n"
  );
}
