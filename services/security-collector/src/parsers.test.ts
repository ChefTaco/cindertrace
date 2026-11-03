import { describe, expect, it } from 'vitest';
import {
  aggregateUnifiLokiEvents,
  parseCef,
  parseDnsmasq,
  parseFlowDatagram,
  parseUnifiLokiEntry,
} from './parsers.js';

describe('Security Fusion source parsers', () => {
  it('parses UniFi CEF without retaining packet contents', () => {
    const event = parseCef('CEF:0|Ubiquiti|UniFi Network|9.3|544|Threat Detected|9|UNIFIcategory=Security UNIFIsubCategory=Intrusion src=10.0.0.2 dst=1.1.1.1 msg=blocked');
    expect(event?.source).toBe('unifi_ids');
    expect(event?.severity).toBe('critical');
  });
  it('parses UDM dnsmasq query activity', () => {
    const event = parseDnsmasq('dnsmasq[1]: query[A] example.com from 10.0.0.5');
    expect(event?.entities).toContainEqual({ type: 'domain', value: 'example.com' });
  });
  it('accepts summaries only for NetFlow v9 and IPFIX v10', () => {
    const packet = Buffer.alloc(20);
    packet.writeUInt16BE(10, 0);
    packet.writeUInt16BE(20, 2);
    expect(parseFlowDatagram(packet, '10.0.0.1')?.attributes).toMatchObject({ packetCapture: false });
    packet.writeUInt16BE(5, 0);
    expect(parseFlowDatagram(packet, '10.0.0.1')).toBeNull();
    expect(parseFlowDatagram(Buffer.from([0, 10, 0]), '10.0.0.1')).toBeNull();
  });
  it('fails closed on malformed CEF and DNS lines', () => {
    expect(parseCef('CEF:0|too|short')).toBeNull();
    expect(parseDnsmasq('reply example.com is 1.2.3.4')).toBeNull();
  });
  it('normalizes UniFi firewall logs without retaining raw messages', () => {
    const events = parseUnifiLokiEntry(
      'gateway-1 [WAN_IN-4000] SRC=198.51.100.8 DST=10.0.0.5 PROTO=UDP SPT=45000 DPT=53',
      { firewall_action: 'drop', firewall_rule_set: 'WAN_IN' },
      new Date('2026-07-27T20:00:30.000Z'),
    );
    expect(events.map((event) => event.source).sort()).toEqual(['netflow', 'unifi_dns', 'unifi_ids']);
    expect(JSON.stringify(events)).not.toContain('gateway-1');
    expect(events.find((event) => event.source === 'netflow')?.attributes).toMatchObject({
      derivedFrom: 'loki-syslog',
      packetCapture: false,
    });
  });
  it('rejects malformed Loki log entries', () => {
    expect(parseUnifiLokiEntry('unstructured log line', {}, new Date())).toEqual([]);
  });
  it('bounds UniFi firewall cardinality with five-minute summaries', () => {
    const rows = Array.from({ length: 500 }, (_, index) => parseUnifiLokiEntry(
      `gateway-1 [WAN_IN-4000] SRC=198.51.100.${index % 250} DST=10.0.0.5 PROTO=UDP SPT=${40000 + index} DPT=53`,
      { firewall_action: 'drop', firewall_rule_set: 'WAN_IN' },
      new Date(`2026-07-27T20:0${index % 5}:30.000Z`),
    )).flat();
    const aggregate = aggregateUnifiLokiEvents(rows);
    expect(aggregate).toHaveLength(3);
    expect(aggregate.map((event) => event.source).sort()).toEqual(['netflow', 'unifi_dns', 'unifi_ids']);
    expect(aggregate.every((event) => event.attributes['observationCount'] === 500)).toBe(true);
    expect(aggregate.every((event) => event.attributes['aggregationWindowMinutes'] === 5)).toBe(true);
    expect(aggregate.flatMap((event) => event.entities)).toEqual(
      expect.arrayContaining([{ type: 'ip', value: '10.0.0.5' }]),
    );
    expect(JSON.stringify(aggregate)).not.toContain('198.51.100.249');
  });
  it('coalesces random high-port scans without losing bounded port samples', () => {
    const rows = Array.from({ length: 500 }, (_, index) => parseUnifiLokiEntry(
      `gateway-1 [WAN_IN-4000] SRC=198.51.100.${index % 250} DST=10.0.0.5 PROTO=TCP SPT=${20000 + index} DPT=${10000 + index}`,
      { firewall_action: 'drop', firewall_rule_set: 'WAN_IN' },
      new Date(`2026-07-27T20:0${index % 5}:30.000Z`),
    )).flat();
    const aggregate = aggregateUnifiLokiEvents(rows);
    expect(aggregate).toHaveLength(2);
    expect(aggregate.every((event) => event.attributes['destinationService'] === 'other-high-ports')).toBe(true);
    expect(aggregate.every((event) => (event.attributes['sampleDestinationPorts'] as string[]).length === 8)).toBe(true);
    expect(aggregate.every((event) => event.attributes['observationCount'] === 500)).toBe(true);
  });
});
