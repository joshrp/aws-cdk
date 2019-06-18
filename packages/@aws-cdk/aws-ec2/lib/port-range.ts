import { Token } from '@aws-cdk/cdk';

/**
 * Protocol for use in Connection Rules
 */
export enum Protocol {
  All = '-1',
  Tcp = 'tcp',
  Udp = 'udp',
  Icmp = 'icmp',
  Icmpv6 = '58',
}

/**
 * Properties to create a port range
 */
export interface PortRangeProps {
  /**
   * The protocol for the range
   */
  ipProtocol: Protocol;

  /**
   * The starting port for the range
   *
   * @default - Not included in the rule
   */
  fromPort?: number;

  /**
   * The ending port for the range
   *
   * @default - Not included in the rule
   */
  toPort?: number;

  /**
   * String representation for this object
   */
  stringRepresentation: string;
}

/**
 * Interface for classes that provide the connection-specification parts of a security group rule
 */
export class PortRange {
  /**
   * A single TCP port
   */
  public static tcpPort(port: number): PortRange {
    return new PortRange({
      ipProtocol: Protocol.Tcp,
      fromPort: port,
      toPort: port,
      stringRepresentation: renderPort(port),
    });
  }

  /**
   * A TCP port range
   */
  public static tcpPortRange(startPort: number, endPort: number) {
    return new PortRange({
      ipProtocol: Protocol.Tcp,
      fromPort: startPort,
      toPort: endPort,
      stringRepresentation: `${renderPort(startPort)}-${renderPort(endPort)}`
    });
  }

  /**
   * Any TCP traffic
   */
  public static allTcp() {
    return new PortRange({
      ipProtocol: Protocol.Tcp,
      fromPort: 0,
      toPort: 65535,
      stringRepresentation: 'ALL PORTS',
    });
  }

  /**
   * A single UDP port
   */
  public static udpPort(port: number): PortRange {
    return new PortRange({
      ipProtocol: Protocol.Udp,
      fromPort: port,
      toPort: port,
      stringRepresentation: `UDP ${renderPort(port)}`,
    });
  }

  /**
   * A UDP port range
   */
  public static udpPortRange(startPort: number, endPort: number) {
    return new PortRange({
      ipProtocol: Protocol.Udp,
      fromPort: startPort,
      toPort: endPort,
      stringRepresentation: `UDP ${renderPort(startPort)}-${renderPort(endPort)}`
    });
  }

  /**
   * Any UDP traffic
   */
  public static allUdp() {
    return new PortRange({
      ipProtocol: Protocol.Udp,
      fromPort: 0,
      toPort: 65535,
      stringRepresentation: 'UDP ALL PORTS',
    });
  }

  /**
   * A specific combination of ICMP type and code
   *
   * @see https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
   */
  public static icmpTypeAndCode(type: number, code: number) {
    return new PortRange({
      ipProtocol: Protocol.Icmp,
      fromPort: type,
      toPort: code,
      stringRepresentation: `ICMP Type ${type} Code ${code}`
    });
  }

  /**
   * All codes for a single ICMP type
   */
  public static icmpType(type: number): PortRange {
    return new PortRange({
      ipProtocol: Protocol.Icmp,
      fromPort: type,
      toPort: -1,
      stringRepresentation: `ICMP Type ${type}`,
    });
  }

  /**
   * ICMP ping (echo) traffic
   */
  public static icmpPing() {
    return PortRange.icmpType(8);
  }

  /**
   * All ICMP traffic
   */
  public static allIcmp() {
    return new PortRange({
      ipProtocol: Protocol.Icmp,
      fromPort: -1,
      toPort: -1,
      stringRepresentation: 'ALL ICMP',
    });
  }

  /**
   * All traffic
   */
  public static allTraffic() {
    return new PortRange({
      ipProtocol: Protocol.All,
      stringRepresentation: 'ALL TRAFFIC',
    });
  }

  /**
   * Whether the rule containing this port range can be inlined into a securitygroup or not.
   */
  public readonly canInlineRule: boolean;

  constructor(private readonly props: PortRangeProps) {
    this.canInlineRule = !Token.isUnresolved(props.fromPort) && !Token.isUnresolved(props.toPort);
  }

  /**
   * Produce the ingress/egress rule JSON for the given connection
   */
  public toRuleJSON(): any {
    return {
      ipProtocol: this.props.ipProtocol,
      fromPort: this.props.fromPort,
      toPort: this.props.toPort,
    };
  }

  public toString(): string {
    return this.props.stringRepresentation;
  }
}

function renderPort(port: number) {
  return Token.isUnresolved(port) ? `{IndirectPort}` : port.toString();
}