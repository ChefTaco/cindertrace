import { describe, expect, it } from 'vitest';
import { aggregateUnifiLokiEvents, parseIpfixLokiEntry, parseUdmLokiEntry } from './parsers.js';

// goflow2 2.2.7 JSON lines as UDM Pro (UniFi Network 11) IPFIX reaches Loki,
// with addresses moved to documentation ranges and MACs replaced.
const ipfixLabels = { job: 'ipfix', exporter: 'GATEWAY', sampling_rate: '512' };
const flow = (overrides: Record<string, unknown> = {}) => JSON.stringify({
  type: 'IPFIX', time_received_ns: 1794965876805354251, sequence_num: 204, sampling_rate: 0,
  sampler_address: '192.0.2.1', time_flow_start_ns: 1794965835237000000, time_flow_end_ns: 1794965844437000000,
  bytes: 626, packets: 5, src_addr: '192.0.2.130', dst_addr: '198.51.100.246', etype: 'IPv4', proto: 'TCP',
  src_port: 34006, dst_port: 443, in_if: 41, out_if: 4, src_mac: '02:00:00:00:00:01', dst_mac: '02:00:00:00:00:02',
  src_vlan: 0, dst_vlan: 0, vlan_id: 0, ip_tos: 0, forwarding_status: 0, ip_ttl: 0, ip_flags: 0, tcp_flags: 24,
  icmp_type: 0, icmp_code: 0, ipv6_flow_label: 0, fragment_id: 0, fragment_offset: 0, src_as: 0, dst_as: 0,
  next_hop: '203.0.113.1', next_hop_as: 0, src_net: '0.0.0.0/0', dst_net: '0.0.0.0/0', bgp_next_hop: '',
  bgp_communities: [], as_path: [], mpls_ttl: [], mpls_label: [], mpls_ip: [], observation_domain_id: 0,
  observation_point_id: 0, layer_stack: [], layer_size: [], ipv6_routing_header_addresses: [], ipv6_routing_header_seg_left: 0,
  ...overrides,
});
const received = new Date('2026-11-18T01:37:56.805Z');

describe('UDM Pro IPFIX flows from Loki', () => {
  it('maps a flow to a netflow event with sampled and estimated counts', () => {
    const [event, ...rest] = parseIpfixLokiEntry(flow(), ipfixLabels, received);
    expect(rest).toEqual([]);
    expect(event).toMatchObject({
      source: 'netflow',
      kind: 'unifi.firewall.flow.summary',
      observedAt: '2026-11-18T01:37:24.437Z',
      entities: [{ type: 'ip', value: '192.0.2.130' }, { type: 'ip', value: '198.51.100.246' }],
    });
    expect(event?.attributes).toMatchObject({
      action: 'observed', protocol: 'TCP', sourcePort: '34006', destinationPort: '443',
      derivedFrom: 'loki-ipfix', packetCapture: false,
      samplingRate: 512, samplingRateSource: 'stream-label',
      sampledBytes: 626, sampledPackets: 5, estimatedBytes: 626 * 512, estimatedPackets: 5 * 512,
    });
    expect(JSON.stringify(event)).not.toContain('02:00:00:00:00:01');
  });
  it('prefers an exporter-announced sampling rate and falls back to unsampled', () => {
    expect(parseIpfixLokiEntry(flow({ sampling_rate: 100 }), ipfixLabels, received)[0]?.attributes)
      .toMatchObject({ samplingRate: 100, samplingRateSource: 'exporter', estimatedBytes: 62_600 });
    expect(parseIpfixLokiEntry(flow(), { job: 'ipfix' }, received)[0]?.attributes)
      .toMatchObject({ samplingRate: 1, samplingRateSource: 'assumed-unsampled', estimatedBytes: 626 });
  });
  it('adds DNS network activity for port 53 flows, as the syslog path did', () => {
    const events = parseIpfixLokiEntry(flow({ proto: 'UDP', src_port: 53211, dst_port: 53, bytes: 74, packets: 1 }), ipfixLabels, received);
    expect(events.map((event) => [event.source, event.kind])).toEqual([
      ['netflow', 'unifi.firewall.flow.summary'],
      ['unifi_dns', 'dns.network-activity'],
    ]);
  });
  it('labels flow direction from address scope', () => {
    const local = '10.0.0.5';
    const direction = (src: string, dst: string) =>
      parseIpfixLokiEntry(flow({ src_addr: src, dst_addr: dst }), ipfixLabels, received)[0]?.attributes['ruleSet'];
    expect(direction(local, '198.51.100.246')).toBe('ipfix-outbound');
    expect(direction('198.51.100.246', local)).toBe('ipfix-inbound');
    expect(direction(local, '10.0.0.6')).toBe('ipfix-internal');
    expect(direction('192.0.2.130', '198.51.100.246')).toBe('ipfix-transit');
  });
  it('drops ports for protocols without them and keeps IPv6 addresses', () => {
    const [event] = parseIpfixLokiEntry(flow({ proto: 'ICMPv6', etype: 'IPv6', src_addr: '2001:DB8::1', dst_addr: '2001:db8::2', src_port: 0, dst_port: 0 }), ipfixLabels, received);
    expect(event?.attributes).toMatchObject({ protocol: 'ICMPV6', sourcePort: undefined, destinationPort: undefined });
    expect(event?.entities[0]).toEqual({ type: 'ip', value: '2001:db8::1' });
  });
  it('uses the Loki time when the exporter clock is implausible', () => {
    const [event] = parseIpfixLokiEntry(flow({ time_flow_end_ns: 0 }), ipfixLabels, received);
    expect(event?.observedAt).toBe(received.toISOString());
  });
  it('rejects records that are not flows', () => {
    for (const line of [
      'not json', '{"type":"IPFIX"', '[]', JSON.stringify({ type: 'SFLOW_5' }),
      flow({ src_addr: 'gateway' }), flow({ bytes: -1 }), flow({ packets: 1.5 }), flow({ proto: '<script>' }),
      `${flow().slice(0, -1)},"pad":"${'x'.repeat(16_384)}"}`,
    ]) expect(parseIpfixLokiEntry(line, ipfixLabels, received)).toEqual([]);
  });
  it('aggregates sampled flows with summed estimates', () => {
    const rows = Array.from({ length: 40 }, (_, index) => parseIpfixLokiEntry(
      flow({ src_port: 30000 + index, time_flow_start_ns: 1794965835237000000 + index }), ipfixLabels, received,
    )).flat();
    const [summary, ...rest] = aggregateUnifiLokiEvents(rows);
    expect(rest).toEqual([]);
    expect(summary?.attributes).toMatchObject({
      derivedFrom: 'loki-ipfix', observationCount: 40, samplingRate: 512,
      sampledBytes: 40 * 626, estimatedBytes: 40 * 626 * 512, estimatedPackets: 40 * 5 * 512, estimatedFlowCount: 40 * 512,
    });
    expect(summary?.summary).toContain('40 sampled TCP flow observations');
    expect(summary?.summary).toContain('estimated at 1 in 512 sampling');
  });
  it('keeps later polls of the same window as separate summaries and replays as duplicates', () => {
    const poll = (offset: number) => parseIpfixLokiEntry(flow({ src_port: 40000 + offset }), ipfixLabels, received);
    const first = aggregateUnifiLokiEvents(poll(1));
    const replay = aggregateUnifiLokiEvents(poll(1));
    const second = aggregateUnifiLokiEvents(poll(2));
    expect(replay[0]?.eventId).toBe(first[0]?.eventId);
    expect(second[0]?.eventId).not.toBe(first[0]?.eventId);
  });
  it('routes IPFIX lines through the UDM dispatcher as observations', () => {
    const parsed = parseUdmLokiEntry(flow(), ipfixLabels, received);
    expect(parsed.alerts).toEqual([]);
    expect(parsed.observations.map((event) => event.source)).toEqual(['netflow']);
  });
});

// The audit line is a real UniFi Network 11.0.99 SIEM line with names and
// addresses replaced; the security lines follow the same layout.
const cefLine = (signature: string, name: string, severity: number, extension: string) =>
  `gateway CEF:0|Ubiquiti|UniFi Network|11.0.99|${signature}|${name}|${severity}|${extension}`;
const auditLine = cefLine('544', 'Network Accessed', 4,
  'UNIFIcategory=Audit UNIFIsite=Example Site UNIFIhost=gateway UNIFIaccessMethod=web UNIFIadmin=Example Admin src=192.0.2.10 UNIFIutcTime=2026-11-18T01:44:34.017Z msg=Example Admin accessed UniFi Network using the web. Source IP: 192.0.2.10');
const lokiTime = new Date('2026-11-18T01:44:34.120Z');

describe('UniFi Network CEF lines from Loki', () => {
  it('skips audit and other non-security categories', () => {
    expect(parseUdmLokiEntry(auditLine, { job: 'syslog' }, lokiTime)).toEqual({ observations: [], alerts: [] });
    expect(parseUdmLokiEntry(cefLine('400', 'WiFi Client Connected', 1, 'UNIFIcategory=Monitoring UNIFIsubCategory=WiFi UNIFIhost=gateway msg=Client connected'), {}, lokiTime).alerts).toEqual([]);
  });
  it('maps threat management to a unifi_ids alert at the reported UTC time', () => {
    const { alerts, observations } = parseUdmLokiEntry(cefLine('546', 'Threat Detected and Blocked', 7,
      'UNIFIcategory=Security UNIFIsubCategory=Intrusion Prevention UNIFIhost=gateway src=198.51.100.23 spt=51515 dst=192.0.2.40 dpt=445 proto=TCP UNIFIutcTime=2026-11-18T01:44:33.900Z msg=ET SCAN Suspicious inbound to SMB'),
    { job: 'syslog' }, lokiTime);
    expect(observations).toEqual([]);
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({
      source: 'unifi_ids', kind: 'unifi.ids.alert', severity: 'high', observedAt: '2026-11-18T01:44:33.900Z',
      summary: 'Threat Detected and Blocked',
      entities: [{ type: 'ip', value: '198.51.100.23' }, { type: 'ip', value: '192.0.2.40' }],
    });
    expect(alerts[0]?.attributes).toMatchObject({
      category: 'Security', subcategory: 'Intrusion Prevention', signature: '546', protocol: 'TCP',
      sourcePort: '51515', destinationPort: '445', derivedFrom: 'loki-cef', packetCapture: false,
    });
  });
  it('maps firewall events to unifi_ids firewall alerts', () => {
    const [alert] = parseUdmLokiEntry(cefLine('300', 'Blocked by Firewall', 3,
      'UNIFIcategory=Security UNIFIsubCategory=Firewall UNIFIhost=gateway src=203.0.113.9 dst=192.0.2.41 dpt=22 proto=TCP act=blocked'),
    {}, lokiTime).alerts;
    expect(alert).toMatchObject({ source: 'unifi_ids', kind: 'unifi.firewall.alert', severity: 'low', confidence: 0.82 });
    expect(alert?.attributes).toMatchObject({ action: 'blocked', destinationPort: '22' });
  });
  it('maps DNS filtering to unifi_dns activity', () => {
    const [alert] = parseUdmLokiEntry(cefLine('620', 'DNS Domain Blocked', 2,
      'UNIFIcategory=Security UNIFIsubCategory=DNS Filtering src=192.0.2.42 dhost=blocked.example msg=Domain blocked'),
    {}, lokiTime).alerts;
    expect(alert).toMatchObject({ source: 'unifi_dns', kind: 'dns.activity' });
    expect(alert?.entities).toContainEqual({ type: 'domain', value: 'blocked.example' });
  });
  it('gives repeated identical lines distinct IDs by time and replays the same ID', () => {
    const line = cefLine('546', 'Threat Detected and Blocked', 7, 'UNIFIcategory=Security UNIFIsubCategory=Intrusion Prevention src=198.51.100.23 dst=192.0.2.40');
    const first = parseUdmLokiEntry(line, {}, lokiTime).alerts[0];
    const replay = parseUdmLokiEntry(line, {}, lokiTime).alerts[0];
    const later = parseUdmLokiEntry(line, {}, new Date(lokiTime.getTime() + 60_000)).alerts[0];
    expect(replay?.eventId).toBe(first?.eventId);
    expect(later?.eventId).not.toBe(first?.eventId);
  });
  it('ignores a UniFi time far from the Loki time and malformed CEF', () => {
    const [alert] = parseUdmLokiEntry(cefLine('546', 'Threat Detected', 7, 'UNIFIcategory=Security UNIFIutcTime=2020-01-01T00:00:00Z src=198.51.100.23'), {}, lokiTime).alerts;
    expect(alert?.observedAt).toBe(lokiTime.toISOString());
    expect(parseUdmLokiEntry('gateway CEF:0|Ubiquiti|UniFi Network|11.0.99|546', {}, lokiTime).alerts).toEqual([]);
  });
  it('still reads legacy firewall syslog lines', () => {
    const { observations, alerts } = parseUdmLokiEntry(
      'gateway [WAN_IN-4000] SRC=198.51.100.8 DST=192.0.2.5 PROTO=UDP SPT=45000 DPT=53',
      { firewall_action: 'drop', firewall_rule_set: 'WAN_IN' }, lokiTime);
    expect(alerts).toEqual([]);
    expect(observations.map((event) => event.source).sort()).toEqual(['netflow', 'unifi_dns', 'unifi_ids']);
  });
});
