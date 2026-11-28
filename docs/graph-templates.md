# Graph Templates

A graph template is a reusable chart definition: which metrics to plot, as
what kind of chart, with which colours and axis label. A host template ties
graph templates to device platforms, so that Plexus creates the graphs of a
device when the device is added. A graph tree is an outline you build by
hand to group devices and their graphs. Use them to define one standard set
of graphs for every device of a kind.

In this version Plexus stores the templates, the host templates, the graphs
they create on each device (host graphs) and the trees, but no page draws
host graphs yet. To see the charts of a device today, use the device detail
page ([Monitoring](monitoring.md#the-device-detail-page)) or a custom
dashboard ([Dashboard](dashboard.md#custom-dashboards)).

## Where it is and what you need

- **Observe > Monitoring > Configure**, sub-tabs **Graph Templates**,
  **Host Templates** and **Graph Trees**. The old address `/graph-templates`
  opens **Graph Templates**.
- You need the `graph-templates` feature. It covers viewing and changing.
- The metrics a template plots come from the monitoring poller, so devices
  must be polled. See [Monitoring](monitoring.md).

## Graph templates

### Create a template

1. On **Graph Templates**, click **+ New Template**.
2. In **New Graph Template**, fill in:

   | Field | Meaning | Default |
   |---|---|---|
   | **Name** | Required, for example `CPU Usage` | |
   | **Description** | Optional | |
   | **Graph Type** | Line, Bar, Gauge or Heatmap | Line |
   | **Scope** | Device (one graph per device) or Interface (one graph per interface) | Device |
   | **Category** | System, Traffic, Availability or Custom, used to filter the list | System |
   | **Title Format** | The graph title. In an interface template, `$interface` and `$ifIndex` are replaced by the interface name and index | the name |
   | **Y-Axis Label** | For example `Bits/sec` | |
   | **Stacked**, **Area Fill** | Stack the series; fill under the lines | off, on |
   | **Grid Width (1-12 columns)**, **Grid Height (1-12 rows)** | The graph's size | 6, 4 |

3. Click **Create**.

### Add the data series

1. Click the template's card to open it.
2. Click **+ Add Series** and fill in **Add Data Series**:

   | Field | Meaning | Default |
   |---|---|---|
   | **Metric** | Required. The metric name; the field suggests names | |
   | **Label** | The legend text | the metric name |
   | **Line Type** | Line, Area, Stacked area or Bar | Area |
   | **Consolidation** | Average or Last value | Average |
   | **Color** | The series colour | `#10b981` |
   | **Sort Order** | The order of the series (0 to 9999) | after the last series |

3. Click **Add**. Each series row has **Edit** and delete. The template's
   own **Edit** and delete are at the bottom of the dialog.

### What a template can plot

A series plots one metric of the device. Use the names the monitoring
poller records: `cpu_percent`, `memory_percent`, `memory_used_mb`,
`memory_total_mb`, `uptime_seconds`, `response_time_ms`, `packet_loss_pct`,
`if_up_count`, `if_down_count`, `vpn_tunnels_up`, `vpn_tunnels_down`,
`route_count`, and the interface error and discard rates
`if_in_errors_rate`, `if_out_errors_rate`, `if_in_discards_rate`,
`if_out_discards_rate`. The raw counters (`if_in_errors` and the others
without `_rate`) are no longer recorded, so a series on one of them has no
new data. See [Metrics collected](monitoring.md#metrics-collected).

The suggestion list of the **Metric** field also offers names that the
poller does not record: `cpu_usage`, `memory_usage`, `uptime`, `ping_rtt`,
`if_in_octets`, `if_out_octets`, `if_utilization_in` and
`if_utilization_out`. A series on one of them has no data.

### Built-in templates

Plexus ships 15 templates with the **Built-in** badge, such as CPU Usage,
Memory Usage, Interface Traffic, Response Time, Packet Loss, System
Overview and VPN Tunnels. They are read-only: they have no **Edit**, delete
or **+ Add Series**. To change one, create a new template with the series
you want.

## Host templates

A host template says which graph templates a device of a given platform
gets.

1. On **Host Templates**, click **+ New Host Template**.
2. Fill in **Name**, **Description** and **Device Types (comma-separated,
   leave empty for all)**, for example `cisco_ios, cisco_nxos`. The device
   types are inventory platforms; empty means every device.
3. Keep **Auto-apply to matching devices** ticked.
4. Tick the **Graph Templates** to apply.
5. Click **Create**.

Each card shows **Auto-apply** or **Manual**, **Devices:** (the platforms
or **All devices**) and the linked graph templates, with **Edit** and
delete.

### When host graphs are created

| Template scope | Graphs are created |
|---|---|
| Device | When a host is added to the inventory, by hand or by discovery: one graph for each device-scoped graph template of every auto-apply host template whose device types include the host's platform (case is ignored) or are empty |
| Interface | When topology discovery reads a host's interfaces: one graph per interface for every interface-scoped graph template, whatever the host templates say |

A graph's title is the template's **Title Format**, or its name. A device
never gets the same graph twice.

## Graph trees

A graph tree is a named outline of header, device and graph nodes. Trees
are stored and edited here only.

1. On **Graph Trees**, click **+ New Tree**, enter a **Name** and an
   optional **Description**, and click **Create**.
2. Click the tree to open it, then **+ Add Node**.
3. Choose the **Type**:

   | Type | Needs |
   |---|---|
   | Header | A **Title**. Use it to group (by site, role or customer) |
   | Device | A **Host**; the title defaults to the host name |
   | Graph | A **Host** and one of its **Graph** entries; the title defaults to the graph title |

4. Choose the **Parent** (**(Top level)** or another node) and the **Sort
   Order**, then click **Add**. Nodes with the same parent are listed by
   sort order. Each node has **Edit** and delete.

A node cannot be moved under itself or one of its own children.

## Rules worth knowing

- **Existing hosts are not updated.** Host templates apply when a host is
  added. A host template created or changed later does not add graphs to
  hosts already in the inventory. Use
  `POST /api/hosts/{host_id}/apply-graph-templates` for those; the page has
  no button for it.
- **Manual host templates** (auto-apply off) are not applied by Plexus.
- **Deleting a graph template** deletes every host graph made from it.
  Built-in templates cannot be changed or deleted (`403`).
- **Deleting a host template** removes its links to graph templates; the
  host graphs it created stay.
- **Deleting a host** deletes its host graphs and its tree nodes. Deleting
  a host graph leaves a graph node without its graph.
- **Deleting a tree** deletes all its nodes. Deleting a node deletes the
  nodes under it.

## Who can do what

| Action | Needs |
|---|---|
| See templates, host templates and trees | The `graph-templates` feature |
| Create, change or delete them, and apply templates to a host | The `graph-templates` feature |

## API

All routes need the `graph-templates` feature. The full list is in
[API reference](api-reference.md).

| Method and path | Purpose |
|---|---|
| `GET /api/graph-templates?category=&scope=&built_in=`, `POST` | List, create |
| `GET/PUT/DELETE /api/graph-templates/{id}` | One template, with its `items` |
| `POST /api/graph-templates/{id}/items`, `PUT/DELETE .../items/{item_id}` | Data series |
| `GET/POST /api/host-templates`, `GET/PUT/DELETE /api/host-templates/{id}` | Host templates |
| `POST/DELETE /api/host-templates/{id}/graph-templates/{graph_template_id}` | Link or unlink a graph template |
| `GET /api/host-graphs?host_id=` | The graphs of a host |
| `POST /api/hosts/{host_id}/apply-graph-templates` | Apply the matching host templates to a host now |
| `GET/POST /api/graph-trees`, `GET/PUT/DELETE /api/graph-trees/{id}`, `/api/graph-trees/{id}/nodes` | Trees and nodes |

Create a template and one series:

```json
POST /api/graph-templates
{
  "name": "Branch CPU",
  "graph_type": "line",
  "scope": "device",
  "category": "custom",
  "y_axis_label": "%",
  "y_min": 0,
  "y_max": 100
}
```

```json
POST /api/graph-templates/21/items
{ "metric_name": "cpu_percent", "label": "CPU", "line_type": "area", "color": "#10b981", "consolidation": "avg" }
```

Link it to a host template and apply it to an existing host:

```
POST /api/host-templates/3/graph-templates/21
POST /api/hosts/42/apply-graph-templates
```

```json
{ "created": 1, "host_graphs": [ { "id": 88, "host_id": 42, "graph_template_id": 21, "title": "Branch CPU" } ] }
```
