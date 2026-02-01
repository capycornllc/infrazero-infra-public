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
  network_id = hcloud_network.main.id
  destination = "0.0.0.0/0"
  gateway     = var.servers.egress.private_ip
}

resource "hcloud_network_route" "wireguard" {
  count       = var.wireguard.enabled ? 1 : 0
  network_id  = hcloud_network.main.id
  destination = local.wg_cidr
  gateway     = var.servers.bastion.private_ip
}

resource "hcloud_placement_group" "bastion" {
  count = var.placement_groups.enabled ? 1 : 0

  name = "${var.name_prefix}-bastion-pg"
  type = var.placement_groups.type
}

resource "hcloud_placement_group" "egress" {
  count = var.placement_groups.enabled ? 1 : 0

  name = "${var.name_prefix}-egress-pg"
  type = var.placement_groups.type
}

resource "hcloud_placement_group" "k3s" {
  count = var.placement_groups.enabled ? 1 : 0

  name = "${var.name_prefix}-k3s-pg"
  type = var.placement_groups.type
}

resource "hcloud_placement_group" "db" {
  count = var.placement_groups.enabled ? 1 : 0

  name = "${var.name_prefix}-db-pg"
  type = var.placement_groups.type
}

locals {
  pg_bastion_id = var.placement_groups.enabled ? hcloud_placement_group.bastion[0].id : null
  pg_egress_id  = var.placement_groups.enabled ? hcloud_placement_group.egress[0].id : null
  pg_k3s_id     = var.placement_groups.enabled ? hcloud_placement_group.k3s[0].id : null
  pg_db_id      = var.placement_groups.enabled ? hcloud_placement_group.db[0].id : null
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
    port       = "any"
    source_ips = var.wireguard.allowed_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "any"
    source_ips = var.wireguard.allowed_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "icmp"
    source_ips = var.wireguard.allowed_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [local.bastion_cidr]
  }
}

resource "hcloud_firewall" "k3s_server" {
  name = "${var.name_prefix}-k3s-server-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "30080"
    source_ips = [local.lb_private_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "30443"
    source_ips = [local.lb_private_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "6443"
    source_ips = concat(var.wireguard.allowed_cidrs, [local.bastion_cidr], local.k3s_agent_cidrs)
  }

  dynamic "rule" {
    for_each = length(local.k3s_agent_cidrs) > 0 ? [1] : []
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = "9345"
      source_ips = local.k3s_agent_cidrs
    }
  }

  dynamic "rule" {
    for_each = length(local.k3s_agent_cidrs) > 0 ? [1] : []
    content {
      direction  = "in"
      protocol   = "udp"
      port       = "8472"
      source_ips = local.k3s_agent_cidrs
    }
  }

  dynamic "rule" {
    for_each = length(local.k3s_agent_cidrs) > 0 ? [1] : []
    content {
      direction  = "in"
      protocol   = "tcp"
      port       = "10250"
      source_ips = local.k3s_agent_cidrs
    }
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

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "8472"
    source_ips = [local.k3s_server_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "10250"
    source_ips = [local.k3s_server_cidr]
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
  placement_group_id = local.pg_bastion_id
  user_data = templatefile("${path.module}/templates/cloud-init.tftpl", {
    bootstrap_role  = "bastion"
    bootstrap_url   = var.bootstrap_artifacts["bastion"].url
    bootstrap_sha256 = var.bootstrap_artifacts["bastion"].sha256
    db_volume_name  = var.db_volume.name
    db_volume_format = var.db_volume.format
    private_cidr    = var.private_cidr
    bastion_private_ip = var.servers.bastion.private_ip
    wg_server_address = var.wg_server_address
    wg_cidr         = var.wireguard.allowed_cidrs[0]
    admin_users_json_b64 = var.admin_users_json_b64
    debug_root_password = local.debug_root_password_escaped
    egress_env      = []
    db_backup_age_private_key = ""
    bastion_env     = concat(local.bastion_env_lines, [
      format("EGRESS_PRIVATE_IP='%s'", var.servers.egress.private_ip),
      format("EGRESS_LOKI_URL='http://%s:3100/loki/api/v1/push'", var.servers.egress.private_ip),
    ])
    node_env        = []
    node_role_env   = []
  })

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
  placement_group_id = local.pg_egress_id
  user_data = templatefile("${path.module}/templates/cloud-init.tftpl", {
    bootstrap_role  = "egress"
    bootstrap_url   = var.bootstrap_artifacts["egress"].url
    bootstrap_sha256 = var.bootstrap_artifacts["egress"].sha256
    db_volume_name  = var.db_volume.name
    db_volume_format = var.db_volume.format
    private_cidr    = var.private_cidr
    bastion_private_ip = var.servers.bastion.private_ip
    wg_server_address = var.wg_server_address
    wg_cidr         = var.wireguard.allowed_cidrs[0]
    admin_users_json_b64 = var.admin_users_json_b64
    debug_root_password = local.debug_root_password_escaped
    egress_env      = local.egress_env_lines
    db_backup_age_private_key = var.db_backup_age_private_key
    bastion_env     = []
    node_env        = []
    node_role_env   = []
  })

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
  firewall_ids       = [each.key == local.k3s_server_key ? hcloud_firewall.k3s_server.id : hcloud_firewall.k3s_agent.id]
  placement_group_id = local.pg_k3s_id
  user_data = templatefile("${path.module}/templates/cloud-init.tftpl", {
    bootstrap_role  = each.key == local.k3s_server_key ? "node1" : "node2"
    bootstrap_url   = var.bootstrap_artifacts[each.key == local.k3s_server_key ? "node1" : "node2"].url
    bootstrap_sha256 = var.bootstrap_artifacts[each.key == local.k3s_server_key ? "node1" : "node2"].sha256
    db_volume_name  = var.db_volume.name
    db_volume_format = var.db_volume.format
    private_cidr    = var.private_cidr
    bastion_private_ip = var.servers.bastion.private_ip
    wg_server_address = var.wg_server_address
    wg_cidr         = var.wireguard.allowed_cidrs[0]
    admin_users_json_b64 = var.admin_users_json_b64
    debug_root_password = local.debug_root_password_escaped
    egress_env      = []
    db_backup_age_private_key = ""
    bastion_env     = []
    node_env        = local.k3s_env_lines
    node_role_env   = each.key == local.k3s_server_key ? local.k3s_server_env_lines : local.k3s_agent_env_lines
  })

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
  placement_group_id = local.pg_db_id
  user_data = templatefile("${path.module}/templates/cloud-init.tftpl", {
    bootstrap_role  = "db"
    bootstrap_url   = var.bootstrap_artifacts["db"].url
    bootstrap_sha256 = var.bootstrap_artifacts["db"].sha256
    db_volume_name  = var.db_volume.name
    db_volume_format = var.db_volume.format
    private_cidr    = var.private_cidr
    bastion_private_ip = var.servers.bastion.private_ip
    wg_server_address = var.wg_server_address
    wg_cidr         = var.wireguard.allowed_cidrs[0]
    admin_users_json_b64 = var.admin_users_json_b64
    debug_root_password = local.debug_root_password_escaped
    egress_env      = []
    db_backup_age_private_key = ""
    bastion_env     = []
    node_env        = []
    node_role_env   = []
  })

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

resource "hcloud_load_balancer_network" "main" {
  load_balancer_id = hcloud_load_balancer.main.id
  network_id       = hcloud_network.main.id
  ip               = var.load_balancer.private_ip
}

resource "hcloud_load_balancer_target" "k3s_server" {
  type             = "server"
  load_balancer_id = hcloud_load_balancer.main.id
  server_id        = hcloud_server.k3s[local.k3s_server_key].id
  use_private_ip   = true
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
