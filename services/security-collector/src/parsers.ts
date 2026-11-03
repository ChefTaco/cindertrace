import { createHash, randomUUID } from 'node:crypto';
import type { SecurityFusionEvent, SecurityFusionSource } from '@cindertrace/contracts';

function eventId(source: string, sourceId: string): string {
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
 * Collapse high-volume UniFi firewall rows into bounded five-minute summaries.
 * Loki remains the detailed source of record; Magnus stores enough dimensions
 * for correlation without creating one event/entity/case row per packet log.
 */
export function aggregateUnifiLokiEvents(events: SecurityFusionEvent[]): SecurityFusionEvent[] {
  const groups = new Map<string, {
    events: SecurityFusionEvent[];
    sources: Set<string>;
    destinations: Set<string>;
    destinationPorts: Set<string>;
    localEntities: Map<string, SecurityFusionEvent['entities'][number]>;
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
    const sourceId = `aggregate:${createHash('sha256').update(key).digest('hex')}`;
    const subject = first.source === 'unifi_dns'
      ? 'DNS network observations'
      : first.source === 'unifi_ids'
        ? action === 'observed'
          ? 'UniFi firewall observations'
          : `UniFi firewall ${action} observations`
        : `${protocol} flow observations`;
    return {
      ...first,
      eventId: eventId(first.source, sourceId),
      sourceEventId: sourceId,
      observedAt: latest,
      severity: mostSevere,
      confidence: Math.max(...group.events.map((event) => event.confidence)),
      summary: `${group.events.length} ${subject} matched ${ruleSet} for destination service ${destinationService}`,
      entities: [...group.localEntities.values()],
      attributes: {
        action,
        ruleSet,
        protocol,
        destinationService,
        sampleDestinationPorts: [...group.destinationPorts],
        derivedFrom: 'loki-syslog',
        packetCapture: false,
        aggregationWindowMinutes: 5,
        observationCount: group.events.length,
        uniqueSourceCount: group.sources.size,
        uniqueDestinationCount: group.destinations.size,
      },
      evidence: [{ sourceLocator: `loki-aggregate:${sourceId}`, mediaType: 'application/json' }],
    };
  });
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
    observedAt: Number.isFinite(Date.parse(timestamp)) ? new Date(timestamp).toISOString() : new Date().toISOString(),
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
