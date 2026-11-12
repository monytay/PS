from Helper_Functions import unwrap
from Control_Functions import control_63

class Helper_Functions():
    def check_modern_rule(rule):
    from_port = unwrap(rule.get("from_port"))
    to_port = unwrap(rule.get("to_port"))
    protocol = unwrap(rule.get("ip_protocol"))
    cidr_ipv4 = unwrap(rule.get("cidr_ipv4"))
    cidr_ipv6 = unwrap(rule.get("cidr_ipv6"))

    cidr_blocks = [cidr_ipv4] if cidr_ipv4 else []
    ipv6_cidr_blocks = [cidr_ipv6] if cidr_ipv6 else []

    return evaluate(from_port, to_port, protocol, cidr_blocks, ipv6_cidr_blocks)

    def evaluate(from_port, to_port, protocol, cidr_v4_list, cidr_v6_list):
        if from_port is None or to_port is None:
            return None
        
        try:
            from_port = int(from_port)
            to_port = int(to_port)
        except (ValueError, TypeError):
            return None
        
        if str(protocol).lower() not in ["tcp", "udp", "-1"]:
            return None
        
        hit_ports = []
        for port in [22, 3389]:
            if from_port <= port <= to_port:
                hit_ports.append(port)
        if not hit_ports:
            return None
        
        if "0.0.0.0/0" in cidr_v4_list:
            return f"Port(s) {hit_ports} open to 0.0.0.0/0 (protocol = {protocol})"
        if "::/0" in cidr_v6_list:
            return f"Port(s) {hit_ports} open to ::/0 (protocol = {protocol})"

        return None