"""The lab's monitoring stack: Prometheus scrapes every machine, Grafana
draws it. The `grafana` role on an Ubuntu appliance installs both (plus the
node exporter for the appliance itself) from the `grafana` pack; the
`metrics` role on a Windows machine installs the Prometheus Windows exporter
(winlab/exporters.py). This module writes what ties them together from the
lab definition: the Prometheus configuration listing every machine with the
metrics role as a target, Grafana's provisioning files, and the dashboards
students start from. The files ride on the pack stick the grafana role
installs from (roles._plug_pack adds them), flat, so FAT is happy.
"""

from __future__ import annotations

import json

from .model import Lab, Node

WINDOWS_PORT = 9182     # windows_exporter
NODE_PORT = 9100        # prometheus-node-exporter on the appliance
PROMETHEUS_PORT = 9090
GRAFANA_PORT = 3000
SCRAPE_INTERVAL = "15s"

# windows_exporter collectors: the base set every machine gets, and the ones
# a role makes worth having.
BASE_COLLECTORS = ("cpu", "logical_disk", "memory", "net", "os", "service", "system", "tcp", "time")
ROLE_COLLECTORS: dict[str, tuple[str, ...]] = {
    "ad-ds": ("ad",),
    "dns": ("dns",),
    "dhcp": ("dhcp",),
    "adcs": ("adcs",),
    "dfs": ("dfsr",),
    "file": ("smb",),
    "iis": ("iis",),
    "rds": ("terminal_services",),
    "sql": ("mssql",),
}


def collectors_for(node: Node) -> list[str]:
    out = list(BASE_COLLECTORS)
    for r in node.roles:
        for c in ROLE_COLLECTORS.get(r, ()):
            if c not in out:
                out.append(c)
    return out


def _address(node: Node, lab: Lab) -> str:
    """How Prometheus reaches a machine: its static address, or its name in
    the lab's DNS when it takes DHCP."""
    for nic in node.nics:
        if nic.ip:
            return nic.ip
    host = (node.hostname or node.id).lower()
    return f"{host}.{lab.domain}" if lab.domain else host


def monitored(lab: Lab) -> list[Node]:
    """The Windows machines with the metrics role, in boot order."""
    return [n for n in lab.node_list() if n.is_windows and "metrics" in n.roles]


def monitors(lab: Lab) -> list[Node]:
    return [n for n in lab.node_list() if "grafana" in n.roles]


def targets(lab: Lab) -> list[dict]:
    """One scrape target per monitored machine, labelled with what it is."""
    out = []
    for n in monitored(lab):
        out.append({
            "node": n.id, "instance": f"{_address(n, lab)}:{WINDOWS_PORT}",
            "labels": {"node": n.id, "os": "windows",
                       "roles": ",".join(r for r in n.roles if r != "metrics") or "none",
                       "image": n.image},
        })
    return out


def prometheus_config(lab: Lab) -> str:
    """prometheus.yml: itself, the appliance's node exporter and every Windows
    machine with the metrics role. Plain YAML written by hand so the lab's
    stdlib-only rule holds."""
    lines = [
        "# winlab: generated from the lab definition; Prometheus scrapes every",
        "# machine with the metrics role. Edit on the machine, then",
        "#   promtool check config /etc/prometheus/prometheus.yml && systemctl reload prometheus",
        "global:",
        f"  scrape_interval: {SCRAPE_INTERVAL}",
        f"  evaluation_interval: {SCRAPE_INTERVAL}",
        "  external_labels:",
        f"    lab: {json.dumps(lab.name)}",
        "",
        "rule_files:",
        "  - /etc/prometheus/rules/*.yml",
        "",
        "scrape_configs:",
        "  - job_name: prometheus",
        "    static_configs:",
        f"      - targets: ['localhost:{PROMETHEUS_PORT}']",
        "  - job_name: node",
        "    static_configs:",
        f"      - targets: ['localhost:{NODE_PORT}']",
        "        labels:",
        "          os: linux",
    ]
    for m in monitors(lab):
        lines[-1:] = [
            "          os: linux",
            f"          node: {json.dumps(m.id)}",
        ]
        break
    ts = targets(lab)
    if ts:
        lines += ["  - job_name: windows", "    static_configs:"]
        for t in ts:
            lines += [f"      - targets: [{json.dumps(t['instance'])}]", "        labels:"]
            lines += [f"          {k}: {json.dumps(v)}" for k, v in t["labels"].items()]
    else:
        lines += ["  # No Windows machine is planned to run the exporter yet: add a target",
                  "  # here by hand, or roles = [..., \"metrics\"] in the lab file."]
    return "\n".join(lines) + "\n"


ALERT_RULES = """# winlab: starter rules. Add your own; Prometheus reloads them with
#   promtool check rules /etc/prometheus/rules/winlab.yml && systemctl reload prometheus
groups:
  - name: winlab
    rules:
      - alert: MachineDown
        expr: up == 0
        for: 2m
        labels:
          severity: page
        annotations:
          summary: "{{ $labels.instance }} is not answering its exporter"
      - alert: DiskAlmostFull
        expr: windows_logical_disk_free_bytes / windows_logical_disk_size_bytes < 0.10
        for: 10m
        labels:
          severity: warn
        annotations:
          summary: "{{ $labels.instance }} {{ $labels.volume }} has under 10% free"
      - alert: ServiceStopped
        expr: windows_service_state{state="running", name=~"dns|dhcpserver|ntds|mssqlserver|w3svc"} == 0
        for: 5m
        labels:
          severity: page
        annotations:
          summary: "{{ $labels.name }} on {{ $labels.instance }} is not running"
"""


def grafana_datasource() -> str:
    return (
        "# winlab: Grafana's data source is the Prometheus on this machine.\n"
        "apiVersion: 1\n"
        "datasources:\n"
        "  - name: Prometheus\n"
        "    uid: winlab-prometheus\n"
        "    type: prometheus\n"
        "    access: proxy\n"
        f"    url: http://localhost:{PROMETHEUS_PORT}\n"
        "    isDefault: true\n"
        "    editable: true\n"
    )


def grafana_dashboards_provider() -> str:
    return (
        "# winlab: dashboards under /var/lib/grafana/dashboards appear in the\n"
        "# 'winlab' folder; the ones you make in the browser are stored beside them.\n"
        "apiVersion: 1\n"
        "providers:\n"
        "  - name: winlab\n"
        "    folder: winlab\n"
        "    type: file\n"
        "    allowUiUpdates: true\n"
        "    options:\n"
        "      path: /var/lib/grafana/dashboards\n"
    )


def _panel(pid: int, title: str, exprs: list[tuple[str, str]], x: int, y: int, w: int = 12, h: int = 8,
           kind: str = "timeseries", unit: str = "", instant: bool = False, description: str = "") -> dict:
    p: dict = {
        "id": pid, "type": kind, "title": title, "description": description,
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "datasource": {"type": "prometheus", "uid": "winlab-prometheus"},
        "targets": [{"refId": chr(65 + i), "expr": e, "legendFormat": legend, "instant": instant}
                    for i, (e, legend) in enumerate(exprs)],
        "fieldConfig": {"defaults": {"unit": unit} if unit else {}, "overrides": []},
        "options": {},
    }
    if kind == "stat":
        p["options"] = {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "background",
                        "graphMode": "none", "textMode": "value_and_name"}
    if kind == "table":
        p["options"] = {"showHeader": True}
    return p


def _dashboard(uid: str, title: str, panels: list[dict], tags: list[str], description: str) -> dict:
    return {
        "uid": uid, "title": title, "description": description, "tags": tags, "editable": True,
        "schemaVersion": 39, "version": 1, "timezone": "browser", "refresh": "30s",
        "time": {"from": "now-1h", "to": "now"},
        "templating": {"list": []}, "annotations": {"list": []}, "panels": panels,
    }


def dashboard_overview(lab: Lab) -> dict:
    """Every machine on one screen: up or down, CPU, free memory, disks, network, services."""
    panels = [
        _panel(1, "Machines answering", [("count(up{job=\"windows\"} == 1)", "up")], 0, 0, 6, 4, "stat",
               description="How many Windows machines Prometheus could scrape at the last interval."),
        _panel(2, "Machines down", [("count(up{job=\"windows\"} == 0) or vector(0)", "down")], 6, 0, 6, 4, "stat"),
        _panel(3, "Up or down, per machine", [("up{job=\"windows\"}", "{{node}}")], 12, 0, 12, 4, "stat",
               description="1 is scraped, 0 is not: the machine is off, the exporter stopped, or the port is blocked."),
        _panel(4, "CPU busy %", [("100 - (avg by (node) (rate(windows_cpu_time_total{mode=\"idle\"}[2m])) * 100)", "{{node}}")],
               0, 4, 12, 8, unit="percent"),
        _panel(5, "Free memory", [("windows_memory_physical_free_bytes or windows_os_physical_memory_free_bytes", "{{node}}")],
               12, 4, 12, 8, unit="bytes"),
        _panel(6, "Disk free %", [("100 * windows_logical_disk_free_bytes{volume!~\"HarddiskVolume.*\"} / windows_logical_disk_size_bytes", "{{node}} {{volume}}")],
               0, 12, 12, 8, unit="percent"),
        _panel(7, "Network, bytes per second", [("rate(windows_net_bytes_received_total[2m])", "{{node}} in"),
                                              ("rate(windows_net_bytes_sent_total[2m])", "{{node}} out")],
               12, 12, 12, 8, unit="Bps"),
        _panel(8, "Services not running (automatic start)",
               [("windows_service_state{state=\"running\"} == 0 and on (node, name) windows_service_start_mode{start_mode=\"auto\"} == 1", "{{node}} {{name}}")],
               0, 20, 24, 8, "table", instant=True,
               description="Services set to start automatically that are not running right now."),
    ]
    return _dashboard("winlab-overview", f"Lab overview: {lab.name}", panels, ["winlab"],
                      "Generated by winlab from the lab definition. Change it, or make your own beside it.")


def dashboard_roles(lab: Lab) -> dict:
    """What the roles are doing: directory, DNS, DHCP, SQL Server, web."""
    panels = [
        _panel(1, "Active Directory: LDAP client sessions", [("windows_ad_ldap_client_sessions", "{{node}}")], 0, 0, 12, 8),
        _panel(2, "Active Directory: binds per second", [("sum by (node) (rate(windows_ad_binds_total[5m]))", "{{node}}")], 12, 0, 12, 8),
        _panel(3, "DNS: queries per second", [("sum by (node) (rate(windows_dns_queries_received_total[5m]))", "{{node}}")], 0, 8, 12, 8),
        _panel(4, "DHCP: leases handed out per hour", [("sum by (node) (increase(windows_dhcp_acks_total[1h]))", "{{node}}")], 12, 8, 12, 8),
        _panel(5, "SQL Server: user connections", [("windows_mssql_genstats_user_connections", "{{node}}")], 0, 16, 8, 8),
        _panel(6, "SQL Server: batch requests per second", [("rate(windows_mssql_sqlstats_batch_requests[2m])", "{{node}}")], 8, 16, 8, 8),
        _panel(7, "SQL Server: buffer cache hit ratio", [("windows_mssql_bufman_buffer_cache_hit_ratio", "{{node}}")], 16, 16, 8, 8, unit="percent"),
        _panel(8, "Web: requests per second", [("sum by (node, site) (rate(windows_iis_requests_total[5m]))", "{{node}} {{site}}")], 0, 24, 24, 8),
    ]
    return _dashboard("winlab-roles", f"Roles: {lab.name}", panels, ["winlab"],
                      "Each panel shows data only on machines whose role turned that collector on "
                      "(ad, dns, dhcp, mssql, iis). An empty panel is a role nobody has, not a fault.")


def stick_files(lab: Lab) -> dict[str, bytes]:
    """What the grafana role copies off the pack stick, flat names."""
    return {
        "prometheus.yml": prometheus_config(lab).encode("utf-8"),
        "prometheus-rules.yml": ALERT_RULES.encode("utf-8"),
        "grafana-datasource.yaml": grafana_datasource().encode("utf-8"),
        "grafana-dashboards.yaml": grafana_dashboards_provider().encode("utf-8"),
        "dash-overview.json": json.dumps(dashboard_overview(lab), indent=1).encode("utf-8"),
        "dash-roles.json": json.dumps(dashboard_roles(lab), indent=1).encode("utf-8"),
    }


def describe(lab: Lab) -> str:
    """For `winlab lab plan`: who monitors whom."""
    mons = monitors(lab)
    if not mons:
        return ""
    ts = targets(lab)
    lines = [f"monitoring: {', '.join(m.id for m in mons)} runs Prometheus ({PROMETHEUS_PORT}) and Grafana ({GRAFANA_PORT})"]
    if ts:
        lines.append("  scrapes: " + ", ".join(f"{t['node']} ({t['instance']})" for t in ts))
    else:
        lines.append("  scrapes nothing yet: no Windows machine has the metrics role")
    return "\n".join(lines)
