provider "hcloud" {
  token = var.hcloud_token
}

resource "hcloud_network" "main" {
  name     = "${var.name_prefix}-net"
  ip_range = var.private_cidr
  labels = {
    project     = var.project
    environment = var.environment
  }
}

resource "hcloud_network_subnet" "main" {
  network_id   = hcloud_network.main.id
  type         = "cloud"
  network_zone = var.network_zone
  ip_range     = var.private_cidr
}

resource "hcloud_network_route" "default_egress" {
  network_id  = hcloud_network.main.id
  destination = "0.0.0.0/0"
  gateway     = var.servers.egress.private_ip
}

resource "hcloud_network_route" "wireguard" {
  count       = var.wireguard.enabled ? 1 : 0
  network_id  = hcloud_network.main.id
  destination = local.wg_cidr
  gateway     = var.servers.bastion.private_ip
}

resource "hcloud_placement_group" "main" {
  count = var.placement_groups.enabled ? 1 : 0

  name = "${var.name_prefix}-pg"
  type = var.placement_groups.type
}

locals {
  pg_main_id = var.placement_groups.enabled ? hcloud_placement_group.main[0].id : null
}

resource "hcloud_ssh_key" "ops" {
  for_each = local.ssh_keys_map

  name       = "${var.name_prefix}-ops-${each.key}"
  public_key = each.value

  labels = {
    project     = var.project
    environment = var.environment
  }
}

resource "hcloud_firewall" "bastion" {
  name = "${var.name_prefix}-bastion-fw"

  dynamic "rule" {
    for_each = var.wireguard.enabled ? [1] : []
    content {
      direction  = "in"
      protocol   = "udp"
      port       = tostring(var.wireguard.listen_port)
      source_ips = ["0.0.0.0/0"]
    }
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "any"
    source_ips = [var.private_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "any"
    source_ips = [var.private_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = [var.private_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = local.bastion_ssh_cidrs
  }
}

resource "hcloud_firewall" "egress" {
  name = "${var.name_prefix}-egress-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = local.egress_service_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = local.egress_service_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = local.egress_service_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "3000"
    source_ips = local.egress_service_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "3100"
    source_ips = local.egress_service_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "8080"
    source_ips = local.egress_service_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [local.bastion_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "6443"
    source_ips = [format("%s/32", hcloud_server.egress.ipv4_address), local.egress_cidr]
  }
}

resource "hcloud_firewall" "k3s_server" {
  name = "${var.name_prefix}-k3s-server-fw"

  dynamic "rule" {
    for_each = local.k3s_lb_ports
    iterator = lb_port
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = lb_port.value
      source_ips = [local.lb_private_cidr]
    }
  }

  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "6443"
    source_ips = concat(
      var.wireguard.allowed_cidrs,
      [local.bastion_cidr, local.egress_cidr],
      local.k3s_node_cidrs,
      local.k3s_ha_enabled ? [local.k3s_api_lb_cidr] : []
    )
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "9345"
    source_ips = concat(local.k3s_node_cidrs, local.k3s_ha_enabled ? [local.k3s_api_lb_cidr] : [])
  }

  dynamic "rule" {
    for_each = local.k3s_ha_enabled ? toset(["2379", "2380"]) : []
    iterator = etcd_port
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = etcd_port.value
      source_ips = local.k3s_control_plane_cidrs
    }
  }

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "8472"
    source_ips = local.k3s_node_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "10250"
    source_ips = local.k3s_control_plane_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = concat(var.wireguard.allowed_cidrs, [local.bastion_cidr])
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = var.wireguard.allowed_cidrs
  }
}

resource "hcloud_firewall" "k3s_agent" {
  name = "${var.name_prefix}-k3s-agent-fw"

  dynamic "rule" {
    for_each = local.k3s_lb_ports
    iterator = lb_port
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = lb_port.value
      source_ips = [local.lb_private_cidr]
    }
  }

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "8472"
    source_ips = local.k3s_node_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "10250"
    source_ips = local.k3s_control_plane_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = concat(var.wireguard.allowed_cidrs, [local.bastion_cidr])
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = var.wireguard.allowed_cidrs
  }
}

resource "hcloud_firewall" "db" {
  name = "${var.name_prefix}-db-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "5432"
    source_ips = local.k3s_node_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = concat(var.wireguard.allowed_cidrs, [local.bastion_cidr])
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = var.wireguard.allowed_cidrs
  }
}

resource "hcloud_server" "bastion" {
  name        = "${var.name_prefix}-bastion"
  image       = var.server_image
  server_type = var.bastion_server_type
  location    = var.location

  public_net {
    ipv4_enabled = var.servers.bastion.public_ipv4
    ipv6_enabled = var.servers.bastion.public_ipv6
  }

  network {
    network_id = hcloud_network.main.id
    ip         = var.servers.bastion.private_ip
  }

  ssh_keys           = local.ssh_key_ids
  firewall_ids       = [hcloud_firewall.bastion.id]
  placement_group_id = local.pg_main_id
  user_data          = local.cloud_init_rendered_bastion

  lifecycle {
    # Hetzner treats user_data as ForceNew; we rebuild servers explicitly via
    # workflow-driven `-replace` rather than replacing on every presigned URL
    # refresh or cloud-init template tweak.
    ignore_changes = [user_data]
  }

  labels = {
    project     = var.project
    environment = var.environment
    role        = "bastion"
  }

  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_server" "egress" {
  name        = "${var.name_prefix}-egress"
  image       = var.server_image
  server_type = var.egress_server_type
  location    = var.location

  public_net {
    ipv4_enabled = var.servers.egress.public_ipv4
    ipv6_enabled = var.servers.egress.public_ipv6
  }

  network {
    network_id = hcloud_network.main.id
    ip         = var.servers.egress.private_ip
  }

  ssh_keys           = local.ssh_key_ids
  firewall_ids       = [hcloud_firewall.egress.id]
  placement_group_id = local.pg_main_id
  user_data          = local.cloud_init_rendered_egress

  lifecycle {
    ignore_changes = [user_data]
  }

  labels = {
    project     = var.project
    environment = var.environment
    role        = "egress"
  }

  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_server" "k3s" {
  for_each = local.k3s_nodes_map

  name        = "${var.name_prefix}-node${tonumber(each.key) + 1}"
  image       = var.server_image
  server_type = var.k3s_node_server_type
  location    = var.location

  public_net {
    ipv4_enabled = each.value.public_ipv4
    ipv6_enabled = each.value.public_ipv6
  }

  network {
    network_id = hcloud_network.main.id
    ip         = each.value.private_ip
  }

  ssh_keys           = local.ssh_key_ids
  firewall_ids       = [tonumber(each.key) < local.k3s_control_planes_count ? hcloud_firewall.k3s_server.id : hcloud_firewall.k3s_agent.id]
  placement_group_id = local.pg_main_id
  user_data          = local.cloud_init_rendered_k3s[each.key]

  lifecycle {
    ignore_changes = [user_data]
  }

  labels = {
    project     = var.project
    environment = var.environment
    role        = each.key == local.k3s_server_key ? "node1" : "node${tonumber(each.key) + 1}"
  }

  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_server" "db" {
  name        = "${var.name_prefix}-db"
  image       = var.server_image
  server_type = var.db_server_type
  location    = var.location

  public_net {
    ipv4_enabled = var.servers.db.public_ipv4
    ipv6_enabled = var.servers.db.public_ipv6
  }

  network {
    network_id = hcloud_network.main.id
    ip         = var.servers.db.private_ip
  }

  ssh_keys           = local.ssh_key_ids
  firewall_ids       = [hcloud_firewall.db.id]
  placement_group_id = local.pg_main_id
  user_data          = local.cloud_init_rendered_db

  lifecycle {
    ignore_changes = [user_data]
  }

  labels = {
    project     = var.project
    environment = var.environment
    role        = "db"
  }

  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_load_balancer" "main" {
  name               = "${var.name_prefix}-lb"
  load_balancer_type = var.load_balancer.type
  location           = var.location

  algorithm {
    type = "round_robin"
  }

  labels = {
    project     = var.project
    environment = var.environment
  }
}

resource "hcloud_load_balancer" "k3s_api" {
  count              = local.k3s_ha_enabled ? 1 : 0
  name               = "${var.name_prefix}-k3s-api-lb"
  load_balancer_type = var.k3s_api_load_balancer.type
  location           = var.location

  algorithm {
    type = "round_robin"
  }

  labels = {
    project     = var.project
    environment = var.environment
    role        = "k3s-api"
  }
}

resource "hcloud_load_balancer_network" "k3s_api" {
  count            = local.k3s_ha_enabled ? 1 : 0
  load_balancer_id = hcloud_load_balancer.k3s_api[0].id
  network_id       = hcloud_network.main.id
  ip               = local.k3s_api_lb_private_ip

  # Prevent flakiness: Hetzner may temporarily report no subnet available if the
  # subnet isn't fully ready yet.
  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_load_balancer_target" "k3s_api" {
  for_each = local.k3s_ha_enabled ? {
    for key, srv in hcloud_server.k3s :
    key => srv
    if tonumber(key) < local.k3s_control_planes_count
  } : {}

  type             = "server"
  load_balancer_id = hcloud_load_balancer.k3s_api[0].id
  server_id        = each.value.id
  use_private_ip   = true

  # Required for use_private_ip; otherwise this can race and fail with
  # "no private networks".
  depends_on = [hcloud_load_balancer_network.k3s_api]
}

resource "hcloud_load_balancer_service" "k3s_api" {
  for_each = local.k3s_ha_enabled ? {
    "6443" = 6443
    "9345" = 9345
  } : {}

  load_balancer_id = hcloud_load_balancer.k3s_api[0].id
  protocol         = "tcp"
  listen_port      = each.value
  destination_port = each.value

  health_check {
    protocol = "tcp"
    port     = each.value
    interval = var.load_balancer.health_check.interval
    timeout  = var.load_balancer.health_check.timeout
    retries  = var.load_balancer.health_check.retries
  }
}

resource "hcloud_load_balancer_network" "main" {
  load_balancer_id = hcloud_load_balancer.main.id
  network_id       = hcloud_network.main.id
  ip               = local.lb_private_ip

  # Prevent flakiness: Hetzner may temporarily report no subnet available if the
  # subnet isn't fully ready yet.
  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_load_balancer_target" "k3s" {
  for_each = hcloud_server.k3s

  type             = "server"
  load_balancer_id = hcloud_load_balancer.main.id
  server_id        = each.value.id
  use_private_ip   = true

  # Required for use_private_ip; otherwise this can race and fail with
  # "no private networks".
  depends_on = [hcloud_load_balancer_network.main]
}

resource "hcloud_load_balancer_service" "http" {
  load_balancer_id = hcloud_load_balancer.main.id
  protocol         = local.lb_services["http"].protocol
  listen_port      = local.lb_services["http"].listen_port
  destination_port = local.lb_services["http"].destination_port

  health_check {
    protocol = var.load_balancer.health_check.protocol
    port     = var.load_balancer.health_check.port
    interval = var.load_balancer.health_check.interval
    timeout  = var.load_balancer.health_check.timeout
    retries  = var.load_balancer.health_check.retries
  }
}

resource "hcloud_load_balancer_service" "https" {
  load_balancer_id = hcloud_load_balancer.main.id
  protocol         = local.lb_services["https"].protocol
  listen_port      = local.lb_services["https"].listen_port
  destination_port = local.lb_services["https"].destination_port

  health_check {
    protocol = var.load_balancer.health_check.protocol
    port     = var.load_balancer.health_check.port
    interval = var.load_balancer.health_check.interval
    timeout  = var.load_balancer.health_check.timeout
    retries  = var.load_balancer.health_check.retries
  }
}

resource "hcloud_load_balancer_service" "extra" {
  for_each = local.lb_extra_services

  load_balancer_id = hcloud_load_balancer.main.id
  protocol         = each.value.protocol
  listen_port      = each.value.listen_port
  destination_port = each.value.destination_port

  health_check {
    protocol = var.load_balancer.health_check.protocol
    port     = var.load_balancer.health_check.port
    interval = var.load_balancer.health_check.interval
    timeout  = var.load_balancer.health_check.timeout
    retries  = var.load_balancer.health_check.retries
  }
}

resource "hcloud_volume" "db" {
  name     = var.db_volume.name
  size     = var.db_volume.size
  location = var.location
  format   = var.db_volume.format

  lifecycle {
    prevent_destroy = true
  }

  labels = {
    project     = var.project
    environment = var.environment
  }
}

resource "hcloud_volume_attachment" "db" {
  volume_id = hcloud_volume.db.id
  server_id = hcloud_server.db.id
  automount = false
}
