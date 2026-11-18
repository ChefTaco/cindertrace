import { createHash, randomUUID } from 'node:crypto';
import type { SecurityFusionEvent, SecurityFusionSource } from '@cindertrace/contracts';

export function eventId(source: string, sourceId: string): string {
  return createHash('sha256').update(`${source}:${sourceId}`).digest('hex');
}

function severity(raw: string | number | undefined): SecurityFusionEvent['severity'] {
  const level = typeof raw === 'number' ? raw : Number(raw ?? 0);
  if (level >= 9) return 'critical';
  if (level >= 7) return 'high';
  if (level >= 4) return 'medium';
  return level > 0 ? 'low' : 'info';
}

export function parseCef(line: string, observedAt = new Date()): SecurityFusionEvent | null {
  const cefStart = line.indexOf('CEF:');
  if (cefStart < 0) return null;
  const parts = line.slice(cefStart).split('|');
  if (parts.length < 7) return null;
  const extension = parts.slice(7).join('|');
  const values: Record<string, string> = {};
  for (const match of extension.matchAll(/(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=([^=]*?)(?=\s[A-Za-z][A-Za-z0-9_]*=|$)/g)) {
    values[match[1]!] = match[2]!.trim();
  }
  const category = `${values['UNIFIcategory'] ?? ''} ${values['UNIFIsubCategory'] ?? ''} ${parts[5] ?? ''}`.toLowerCase();
  const source: SecurityFusionSource = category.includes('dns') ? 'unifi_dns' : 'unifi_ids';
  const sourceId = values['eventId'] ?? values['UNIFIeventId'] ?? createHash('sha256').update(line).digest('hex');
  const entities: SecurityFusionEvent['entities'] = [];
  if (values['src']) entities.push({ type: 'ip', value: values['src'] });
  if (values['dst']) entities.push({ type: 'ip', value: values['dst'] });
  if (values['dhost']) entities.push({ type: 'domain', value: values['dhost'] });
  if (values['suser'] ?? values['UNIFIadmin']) entities.push({ type: 'user', value: values['suser'] ?? values['UNIFIadmin']! });
  return {
    schemaVersion: '1.0', eventId: eventId(source, sourceId), source, sourceEventId: sourceId,
    kind: source === 'unifi_dns' ? 'dns.activity' : 'unifi.ids.alert',
    observedAt: observedAt.toISOString(), severity: severity(parts[6]), confidence: source === 'unifi_ids' ? 0.9 : 0.72,
    summary: (parts[5] ?? values['msg'] ?? 'UniFi security event').slice(0, 2000),
    entities, attributes: { category: values['UNIFIcategory'], subcategory: values['UNIFIsubCategory'], signature: parts[4], message: values['msg'] },
    evidence: [{ sourceLocator: `unifi-cef:${sourceId}`, mediaType: 'application/cef' }],
  };
}

export function parseDnsmasq(line: string, observedAt = new Date()): SecurityFusionEvent | null {
  const match = line.match(/query\[(?<type>[A-Z0-9]+)\]\s+(?<domain>\S+)\s+from\s+(?<client>[0-9a-fA-F:.]+)/);
  if (!match?.groups) return null;
  const client = match.groups['client'];
  const domain = match.groups['domain'];
  const queryType = match.groups['type'];
  if (!client || !domain || !queryType) return null;
  const sourceId = createHash('sha256').update(`${observedAt.toISOString().slice(0, 16)}:${client}:${domain}:${queryType}`).digest('hex');
  return {
    schemaVersion: '1.0', eventId: eventId('unifi_dns', sourceId), source: 'unifi_dns', sourceEventId: sourceId,
    kind: 'dns.query', observedAt: observedAt.toISOString(), severity: 'info', confidence: 0.78,
    summary: `${client} queried ${domain}`,
    entities: [{ type: 'ip', value: client }, { type: 'domain', value: domain }],
    attributes: { queryType }, evidence: [{ sourceLocator: `udm-dnsmasq:${sourceId}`, mediaType: 'text/plain' }],
  };
}

export function parseFlowDatagram(buffer: Buffer, address: string, observedAt = new Date()): SecurityFusionEvent | null {
  if (buffer.length < 4) return null;
  const version = buffer.readUInt16BE(0);
  if (version !== 9 && version !== 10) return null;
  const countOrLength = buffer.readUInt16BE(2);
  const sourceId = `${address}:${version}:${observedAt.toISOString().slice(0, 16)}:${createHash('sha256').update(buffer).digest('hex').slice(0, 16)}`;
  return {
    schemaVersion: '1.0', eventId: eventId('netflow', sourceId), source: 'netflow', sourceEventId: sourceId,
    kind: version === 10 ? 'ipfix.summary' : 'netflow.v9.summary', observedAt: observedAt.toISOString(),
    severity: 'info', confidence: 0.75, summary: `${version === 10 ? 'IPFIX' : 'NetFlow v9'} summary from ${address}`,
    entities: [{ type: 'ip', value: address, label: 'flow exporter' }],
    attributes: { version, countOrLength, datagramBytes: buffer.length, packetCapture: false },
    evidence: [{ sourceLocator: `udp-flow:${sourceId}`, mediaType: 'application/octet-stream' }],
  };
}

export function parseUnifiLokiEntry(
  line: string,
  labels: Record<string, string>,
  observedAt: Date,
): SecurityFusionEvent[] {
  const fields = Object.fromEntries(
    [...line.matchAll(/\b([A-Z][A-Z0-9_]*)=(?:"([^"]*)"|(\S+))/gu)]
      .map((match) => [match[1]!, match[2] ?? match[3] ?? '']),
  );
  const src = fields['SRC'];
  const dst = fields['DST'];
  const protocol = fields['PROTO']?.toUpperCase();
  if (!src || !dst || !protocol) return [];
  const sourcePort = fields['SPT'];
  const destinationPort = fields['DPT'];
  const action = (labels['firewall_action'] ?? fields['ACTION'] ?? '').toLowerCase();
  const ruleSet = labels['firewall_rule_set'] ?? fields['RULESET'] ?? line.match(/\[([^\]]+)\]/u)?.[1] ?? 'unknown';
  const minute = observedAt.toISOString().slice(0, 16);
  const entities: SecurityFusionEvent['entities'] = [
    { type: 'ip', value: src },
    { type: 'ip', value: dst },
  ];
  const sharedAttributes = {
    action: action || 'observed',
    ruleSet,
    protocol,
    sourcePort,
    destinationPort,
    derivedFrom: 'loki-syslog',
    packetCapture: false,
  };
  const events: SecurityFusionEvent[] = [];
  const flowSourceId = `${minute}:${src}:${dst}:${protocol}:${sourcePort ?? '-'}:${destinationPort ?? '-'}`;
  events.push({
    schemaVersion: '1.0',
    eventId: eventId('netflow', flowSourceId),
    source: 'netflow',
    sourceEventId: flowSourceId,
    kind: 'unifi.firewall.flow.summary',
    observedAt: observedAt.toISOString(),
    severity: 'info',
    confidence: 0.72,
    summary: `${protocol} flow ${src}:${sourcePort ?? '-'} → ${dst}:${destinationPort ?? '-'}`,
    entities,
    attributes: sharedAttributes,
    evidence: [{ sourceLocator: `loki:${flowSourceId}`, mediaType: 'application/json' }],
  });
  if (action === 'drop' || action === 'reject' || /(?:^|_)WAN(?:_|$)/iu.test(ruleSet)) {
    const idsSourceId = `${minute}:${action || 'firewall'}:${src}:${dst}:${protocol}:${destinationPort ?? '-'}`;
    events.push({
      schemaVersion: '1.0',
      eventId: eventId('unifi_ids', idsSourceId),
      source: 'unifi_ids',
      sourceEventId: idsSourceId,
      kind: 'unifi.firewall.alert',
      observedAt: observedAt.toISOString(),
      severity: action === 'reject' ? 'medium' : 'low',
      confidence: 0.82,
      summary: `UniFi firewall ${action || 'alert'} from ${src} to ${dst}:${destinationPort ?? '-'}`,
      entities,
      attributes: sharedAttributes,
      evidence: [{ sourceLocator: `loki:${idsSourceId}`, mediaType: 'application/json' }],
    });
  }
  if (sourcePort === '53' || destinationPort === '53') {
    const dnsSourceId = `${minute}:${src}:${dst}:${protocol}:${sourcePort ?? '-'}:${destinationPort ?? '-'}`;
    events.push({
      schemaVersion: '1.0',
      eventId: eventId('unifi_dns', dnsSourceId),
      source: 'unifi_dns',
      sourceEventId: dnsSourceId,
      kind: 'dns.network-activity',
      observedAt: observedAt.toISOString(),
      severity: 'info',
      confidence: 0.68,
      summary: `DNS network activity between ${src} and ${dst}`,
      entities,
      attributes: sharedAttributes,
      evidence: [{ sourceLocator: `loki:${dnsSourceId}`, mediaType: 'application/json' }],
    });
  }
  return events;
}

const flowProtocols = new Set(['TCP', 'UDP', 'SCTP', 'UDPLITE']);

function flowAddress(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length > 64) return undefined;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/u.test(value)) return value;
  return /^[0-9a-f:.]+$/iu.test(value) && value.includes(':') ? value.toLowerCase() : undefined;
}

function flowCount(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : undefined;
}

function flowPort(value: unknown): string | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 65_535 ? String(value) : undefined;
}

function flowDirection(source: string, destination: string): string {
  const sourceLocal = isLocalAddress(source);
  const destinationLocal = isLocalAddress(destination);
  if (sourceLocal && destinationLocal) return 'internal';
  if (sourceLocal) return 'outbound';
  if (destinationLocal) return 'inbound';
  return 'transit';
}

/**
 * Normalize one IPFIX/NetFlow v9 flow record that goflow2 wrote as a JSON line
 * and Loki stores (for example `{job="ipfix", exporter="..."}`). It produces the
 * same `netflow` and `unifi_dns` events as the firewall syslog lines did.
 *
 * Exporters such as the UDM Pro sample flows (1 in N). `bytes` and `packets` are
 * the sampled counts; the estimated totals multiply them by the sampling rate,
 * read from the record's `sampling_rate` when the exporter announced it, else
 * from the stream's `sampling_rate` label, else 1 (reported as `samplingRateSource`).
 */
export function parseIpfixLokiEntry(
  line: string,
  labels: Record<string, string>,
  observedAt: Date,
): SecurityFusionEvent[] {
  if (!line.startsWith('{') || line.length > 16_384) return [];
  let record: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(line);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return [];
    record = parsed as Record<string, unknown>;
  } catch {
    return [];
  }
  const flowType = record['type'];
  if (flowType !== 'IPFIX' && flowType !== 'NETFLOW_V9') return [];
  const src = flowAddress(record['src_addr']);
  const dst = flowAddress(record['dst_addr']);
  const rawProtocol = record['proto'];
  const protocol = typeof rawProtocol === 'string' && /^[A-Za-z0-9_-]{1,16}$/u.test(rawProtocol)
    ? rawProtocol.toUpperCase()
    : typeof rawProtocol === 'number' && Number.isInteger(rawProtocol) && rawProtocol >= 0 && rawProtocol <= 255
      ? String(rawProtocol)
      : undefined;
  const sampledBytes = flowCount(record['bytes']);
  const sampledPackets = flowCount(record['packets']);
  if (!src || !dst || !protocol || sampledBytes === undefined || sampledPackets === undefined) return [];
  const sourcePort = flowProtocols.has(protocol) ? flowPort(record['src_port']) : undefined;
  const destinationPort = flowProtocols.has(protocol) ? flowPort(record['dst_port']) : undefined;
  const recordRate = flowCount(record['sampling_rate']);
  const labelRate = Number(labels['sampling_rate']);
  const [samplingRate, samplingRateSource] = recordRate && recordRate > 0
    ? [recordRate, 'exporter']
    : Number.isSafeInteger(labelRate) && labelRate > 0
      ? [labelRate, 'stream-label']
      : [1, 'assumed-unsampled'];
  // Flow end time places the flow in its aggregation window; fall back to the
  // Loki receive time when the exporter clock is implausible.
  const endNs = record['time_flow_end_ns'];
  const endMs = typeof endNs === 'number' && Number.isFinite(endNs) ? Math.floor(endNs / 1_000_000) : NaN;
  const flowEnd = Number.isFinite(endMs) && endMs <= observedAt.getTime() + 5 * 60_000 && endMs >= observedAt.getTime() - 60 * 60_000
    ? new Date(endMs)
    : observedAt;
  const startNs = typeof record['time_flow_start_ns'] === 'number' ? String(record['time_flow_start_ns']) : '-';
  const exporter = flowAddress(record['sampler_address']) ?? labels['exporter'] ?? 'exporter';
  const entities: SecurityFusionEvent['entities'] = [
    { type: 'ip', value: src },
    { type: 'ip', value: dst },
  ];
  const sharedAttributes = {
    action: 'observed',
    ruleSet: `ipfix-${flowDirection(src, dst)}`,
    protocol,
    sourcePort,
    destinationPort,
    derivedFrom: 'loki-ipfix',
    packetCapture: false,
    samplingRate,
    samplingRateSource,
    sampledBytes,
    sampledPackets,
    estimatedBytes: sampledBytes * samplingRate,
    estimatedPackets: sampledPackets * samplingRate,
  };
  const flowKey = `${exporter}:${startNs}:${src}:${dst}:${protocol}:${sourcePort ?? '-'}:${destinationPort ?? '-'}`;
  const events: SecurityFusionEvent[] = [{
    schemaVersion: '1.0',
    eventId: eventId('netflow', flowKey),
    source: 'netflow',
    sourceEventId: flowKey,
    kind: 'unifi.firewall.flow.summary',
    observedAt: flowEnd.toISOString(),
    severity: 'info',
    confidence: 0.75,
    summary: `${protocol} flow ${src}:${sourcePort ?? '-'} → ${dst}:${destinationPort ?? '-'}`,
    entities,
    attributes: sharedAttributes,
    evidence: [{ sourceLocator: `loki:${flowKey}`, mediaType: 'application/json' }],
  }];
  if (sourcePort === '53' || destinationPort === '53') {
    events.push({
      schemaVersion: '1.0',
      eventId: eventId('unifi_dns', flowKey),
      source: 'unifi_dns',
      sourceEventId: flowKey,
      kind: 'dns.network-activity',
      observedAt: flowEnd.toISOString(),
      severity: 'info',
      confidence: 0.68,
      summary: `DNS network activity between ${src} and ${dst}`,
      entities,
      attributes: sharedAttributes,
      evidence: [{ sourceLocator: `loki:${flowKey}`, mediaType: 'application/json' }],
    });
  }
  return events;
}

function cefExtension(line: string): { header: string[]; values: Record<string, string> } | null {
  const cefStart = line.indexOf('CEF:');
  if (cefStart < 0) return null;
  const parts = line.slice(cefStart).split('|');
  if (parts.length < 8) return null;
  const values: Record<string, string> = {};
  for (const match of parts.slice(7).join('|').matchAll(/(?:^|\s)([A-Za-z][A-Za-z0-9_]*)=([^=]*?)(?=\s[A-Za-z][A-Za-z0-9_]*=|$)/g)) {
    values[match[1]!] = match[2]!.trim();
  }
  return { header: parts.slice(0, 7), values };
}

const unifiThreatPattern = /threat|intrusion|\bips\b|\bids\b|honeypot|malware|botnet|attack|exploit|scan/u;

/**
 * A UniFi Network CEF line (Activity Logging to a SIEM server) as Loki stores it:
 * the syslog message, possibly prefixed by the gateway's hostname.
 *
 * Only security events are kept: threat management, intrusion prevention and
 * honeypot hits become `unifi_ids` alerts, firewall events `unifi_ids` firewall
 * alerts, and DNS filtering `unifi_dns` activity. Audit, monitoring, client,
 * device and system events (for example an administrator opening UniFi Network)
 * return null: as `unifi_ids` events they would correlate with Wazuh as an
 * endpoint intrusion. UniFi sends no per-event ID, so the source ID covers the
 * event's time and the line.
 */
export function parseUnifiCefLokiEntry(line: string, observedAt: Date): SecurityFusionEvent | null {
  const cef = cefExtension(line);
  if (!cef) return null;
  const { header, values } = cef;
  const category = (values['UNIFIcategory'] ?? '').toLowerCase();
  const subcategory = (values['UNIFIsubCategory'] ?? '').toLowerCase();
  const name = (header[5] ?? '').toLowerCase();
  const text = `${category} ${subcategory} ${name}`;
  const firewall = !unifiThreatPattern.test(`${subcategory} ${name}`) && `${subcategory} ${name}`.includes('firewall');
  const source: SecurityFusionSource | null = /\bdns\b|domain/u.test(`${subcategory} ${name}`) && !unifiThreatPattern.test(text)
    ? 'unifi_dns'
    : firewall || unifiThreatPattern.test(text)
      ? 'unifi_ids'
      : null;
  if (!source || !header[5]) return null;
  const reported = Date.parse(values['UNIFIutcTime'] ?? '');
  const eventTime = Number.isFinite(reported) && Math.abs(reported - observedAt.getTime()) <= 24 * 3_600_000
    ? new Date(reported)
    : observedAt;
  const event = parseCef(line, eventTime);
  if (!event) return null;
  const sourceId = values['eventId'] ?? values['UNIFIeventId']
    ?? createHash('sha256').update(`${eventTime.toISOString()}|${line.slice(line.indexOf('CEF:'))}`).digest('hex');
  const kind = source === 'unifi_dns' ? 'dns.activity' : firewall ? 'unifi.firewall.alert' : 'unifi.ids.alert';
  const protocol = values['proto']?.toUpperCase();
  return {
    ...event,
    source,
    kind,
    eventId: eventId(source, sourceId),
    sourceEventId: sourceId,
    confidence: source === 'unifi_dns' ? 0.72 : firewall ? 0.82 : 0.9,
    attributes: {
      ...event.attributes,
      ...(protocol ? { protocol } : {}),
      ...(values['spt'] ? { sourcePort: values['spt'] } : {}),
      ...(values['dpt'] ? { destinationPort: values['dpt'] } : {}),
      ...(values['act'] ? { action: values['act'].toLowerCase() } : {}),
      derivedFrom: 'loki-cef',
      packetCapture: false,
    },
    evidence: [{ sourceLocator: `unifi-cef:${sourceId}`, mediaType: 'application/cef' }],
  };
}

/**
 * One Loki entry from the UDM Pro's streams: an IPFIX flow (goflow2 JSON), a
 * CEF line from UniFi Network's SIEM export, or a legacy iptables-style
 * firewall line. Observations are aggregated before ingest; alerts are not.
 */
export function parseUdmLokiEntry(
  line: string,
  labels: Record<string, string>,
  observedAt: Date,
): { observations: SecurityFusionEvent[]; alerts: SecurityFusionEvent[] } {
  if (labels['job'] === 'ipfix' || line.startsWith('{'))
    return { observations: parseIpfixLokiEntry(line, labels, observedAt), alerts: [] };
  if (line.includes('CEF:')) {
    const event = parseUnifiCefLokiEntry(line, observedAt);
    return { observations: [], alerts: event ? [event] : [] };
  }
  return { observations: parseUnifiLokiEntry(line, labels, observedAt), alerts: [] };
}

function isLocalAddress(value: string): boolean {
  const parts = value.split('.').map(Number);
  if (parts.length === 4 && parts.every((part) => Number.isInteger(part) && part >= 0 && part <= 255)) {
    return parts[0] === 10
      || (parts[0] === 172 && (parts[1] ?? 0) >= 16 && (parts[1] ?? 0) <= 31)
      || (parts[0] === 192 && parts[1] === 168)
      || (parts[0] === 100 && (parts[1] ?? 0) >= 64 && (parts[1] ?? 0) <= 127)
      || parts[0] === 127;
  }
  const normalized = value.toLowerCase();
  return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:');
}

const eventSeverityRank: Record<SecurityFusionEvent['severity'], number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const namedServicePorts = new Set([
  1883, 2375, 2376, 3000, 3306, 3389, 5432, 5672, 6379, 6443,
  8080, 8443, 8883, 9000, 9090, 9100, 9200, 9300, 9443, 27017,
]);

function destinationServiceClass(raw: unknown): string {
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return '-';
  if (port <= 1023 || namedServicePorts.has(port)) return String(port);
  return 'other-high-ports';
}

/**
 * Collapse high-volume UniFi firewall rows and IPFIX flows into bounded
 * five-minute summaries. Loki remains the detailed source of record; Cindertrace
 * stores enough dimensions for correlation without one event/entity/case row per
 * packet log or flow.
 *
 * A summary's ID covers its window and the exact rows it counts, so the next
 * poll's rows for the same window become a second summary instead of a
 * duplicate that ingest would drop, while a replay of the same rows stays a
 * duplicate. Sampled flow counts are summed as recorded and as estimated totals.
 */
export function aggregateUnifiLokiEvents(events: SecurityFusionEvent[]): SecurityFusionEvent[] {
  const groups = new Map<string, {
    events: SecurityFusionEvent[];
    sources: Set<string>;
    destinations: Set<string>;
    destinationPorts: Set<string>;
    localEntities: Map<string, SecurityFusionEvent['entities'][number]>;
    volume?: { sampledBytes: number; sampledPackets: number; estimatedBytes: number; estimatedPackets: number; estimatedFlows: number; samplingRates: Set<number> };
  }>();
  for (const event of events) {
    if (!['netflow', 'unifi_dns', 'unifi_ids'].includes(event.source)) continue;
    const observedAt = new Date(event.observedAt);
    observedAt.setUTCMinutes(Math.floor(observedAt.getUTCMinutes() / 5) * 5, 0, 0);
    const bucket = observedAt.toISOString();
    const attributes = event.attributes;
    const destinationService = destinationServiceClass(attributes['destinationPort']);
    const key = [
      bucket,
      event.source,
      event.kind,
      String(attributes['action'] ?? 'observed'),
      String(attributes['ruleSet'] ?? 'unknown'),
      String(attributes['protocol'] ?? 'unknown'),
      destinationService,
    ].join('|');
    const group = groups.get(key) ?? {
      events: [],
      sources: new Set<string>(),
      destinations: new Set<string>(),
      destinationPorts: new Set<string>(),
      localEntities: new Map<string, SecurityFusionEvent['entities'][number]>(),
    };
    group.events.push(event);
    if (typeof attributes['samplingRate'] === 'number') {
      const volume = group.volume ??= { sampledBytes: 0, sampledPackets: 0, estimatedBytes: 0, estimatedPackets: 0, estimatedFlows: 0, samplingRates: new Set<number>() };
      volume.sampledBytes += Number(attributes['sampledBytes'] ?? 0);
      volume.sampledPackets += Number(attributes['sampledPackets'] ?? 0);
      volume.estimatedBytes += Number(attributes['estimatedBytes'] ?? 0);
      volume.estimatedPackets += Number(attributes['estimatedPackets'] ?? 0);
      volume.estimatedFlows += attributes['samplingRate'];
      volume.samplingRates.add(attributes['samplingRate']);
    }
    const ips = event.entities.filter((entity) => entity.type === 'ip');
    if (ips[0]) group.sources.add(ips[0].value);
    if (ips[1]) group.destinations.add(ips[1].value);
    if (attributes['destinationPort'] && group.destinationPorts.size < 8) {
      group.destinationPorts.add(String(attributes['destinationPort']));
    }
    for (const entity of ips) {
      if (isLocalAddress(entity.value) && group.localEntities.size < 8) {
        group.localEntities.set(`${entity.type}:${entity.value}`, entity);
      }
    }
    groups.set(key, group);
  }

  return [...groups.entries()].map(([key, group]) => {
    const first = group.events[0]!;
    const latest = group.events.reduce((value, event) => event.observedAt > value ? event.observedAt : value, first.observedAt);
    const mostSevere = group.events.reduce(
      (value, event) => eventSeverityRank[event.severity] > eventSeverityRank[value] ? event.severity : value,
      first.severity,
    );
    const attributes = first.attributes;
    const action = String(attributes['action'] ?? 'observed');
    const ruleSet = String(attributes['ruleSet'] ?? 'unknown');
    const protocol = String(attributes['protocol'] ?? 'unknown');
    const destinationService = destinationServiceClass(attributes['destinationPort']);
    const members = group.events.map((event) => event.eventId).sort().join(',');
    const sourceId = `aggregate:${createHash('sha256').update(`${key}|${members}`).digest('hex')}`;
    const subject = first.source === 'unifi_dns'
      ? 'DNS network observations'
      : first.source === 'unifi_ids'
        ? action === 'observed'
          ? 'UniFi firewall observations'
          : `UniFi firewall ${action} observations`
        : `${protocol} flow observations`;
    const derivedFrom = String(attributes['derivedFrom'] ?? 'loki-syslog');
    const volume = group.volume;
    const rates = volume ? [...volume.samplingRates] : [];
    const volumeSummary = volume
      ? `; about ${volume.estimatedBytes} bytes in ${volume.estimatedPackets} packets estimated at ${rates.length === 1 ? `1 in ${rates[0]}` : 'mixed'} sampling`
      : '';
    return {
      ...first,
      eventId: eventId(first.source, sourceId),
      sourceEventId: sourceId,
      observedAt: latest,
      severity: mostSevere,
      confidence: Math.max(...group.events.map((event) => event.confidence)),
      summary: `${group.events.length} ${volume ? 'sampled ' : ''}${subject} matched ${ruleSet} for destination service ${destinationService}${volumeSummary}`,
      entities: [...group.localEntities.values()],
      attributes: {
        action,
        ruleSet,
        protocol,
        destinationService,
        sampleDestinationPorts: [...group.destinationPorts],
        derivedFrom,
        packetCapture: false,
        ...(volume ? {
          samplingRate: rates.length === 1 ? rates[0] : Math.max(...rates),
          sampledBytes: volume.sampledBytes,
          sampledPackets: volume.sampledPackets,
          estimatedBytes: volume.estimatedBytes,
          estimatedPackets: volume.estimatedPackets,
          estimatedFlowCount: volume.estimatedFlows,
        } : {}),
        aggregationWindowMinutes: 5,
        observationCount: group.events.length,
        uniqueSourceCount: group.sources.size,
        uniqueDestinationCount: group.destinations.size,
      },
      evidence: [{ sourceLocator: `loki-aggregate:${sourceId}`, mediaType: 'application/json' }],
    };
  });
}

// Upstream zero times (Go `0001-01-01T00:00:00Z`, e.g. Tailscale `LastSeen` for a
// peer that is online now) and the Unix epoch mean "unknown"; use receive time.
const earliestPlausibleTime = Date.parse('2000-01-01T00:00:00.000Z');
export function plausibleTime(value: string, now = new Date()): string {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && parsed >= earliestPlausibleTime ? new Date(parsed).toISOString() : now.toISOString();
}

export function externalEvent(source: 'tailscale' | 'hive' | 'chattermost', row: Record<string, unknown>): SecurityFusionEvent {
  const sourceId = String(row['id'] ?? row['eventId'] ?? row['requestId'] ?? randomUUID());
  const timestamp = String(row['timestamp'] ?? row['createdAt'] ?? row['logged'] ?? new Date().toISOString());
  const actor = row['actorEmail'] ?? row['actor'] ?? row['user'];
  const host = row['hostName'] ?? row['hostname'] ?? row['node'];
  const ip = row['ipAddress'] ?? row['src'];
  return {
    schemaVersion: '1.0', eventId: eventId(source, sourceId), source, sourceEventId: sourceId,
    kind: String(row['eventType'] ?? row['action'] ?? row['kind'] ?? `${source}.event`),
    observedAt: plausibleTime(timestamp),
    severity: severity(row['severity'] as string | number | undefined),
    confidence: source === 'tailscale' ? 0.9 : source === 'hive' ? 0.9 : 0.86,
    summary: String(row['summary'] ?? row['title'] ?? row['action'] ?? `${source} security event`).slice(0, 2000),
    entities: [
      ...(actor ? [{ type: 'user' as const, value: String(actor) }] : []),
      ...(host ? [{ type: 'host' as const, value: String(host) }] : []),
      ...(ip ? [{ type: 'ip' as const, value: String(ip) }] : []),
    ],
    attributes: row, evidence: [{ sourceLocator: `${source}:${sourceId}`, mediaType: 'application/json' }],
  };
}
