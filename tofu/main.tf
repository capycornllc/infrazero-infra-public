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

resource "hcloud_placement_group" "node1" {
  count = var.placement_groups.enabled ? 1 : 0

  name = "${var.name_prefix}-node1-pg"
  type = var.placement_groups.type
}

resource "hcloud_placement_group" "node2" {
  count = var.placement_groups.enabled ? 1 : 0

  name = "${var.name_prefix}-node2-pg"
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
  pg_node1_id   = var.placement_groups.enabled ? hcloud_placement_group.node1[0].id : null
  pg_node2_id   = var.placement_groups.enabled ? hcloud_placement_group.node2[0].id : null
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
    port       = "22"
    source_ips = var.wireguard.allowed_cidrs
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
    port       = "22"
    source_ips = [local.bastion_cidr]
  }
}

resource "hcloud_firewall" "node1" {
  name = "${var.name_prefix}-node1-fw"

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
    source_ips = [local.bastion_cidr, local.node2_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "9345"
    source_ips = [local.node2_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "8472"
    source_ips = [local.node2_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "10250"
    source_ips = [local.node2_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [local.bastion_cidr]
  }
}

resource "hcloud_firewall" "node2" {
  name = "${var.name_prefix}-node2-fw"

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "8472"
    source_ips = [local.node1_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "10250"
    source_ips = [local.node1_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [local.bastion_cidr]
  }
}

resource "hcloud_firewall" "db" {
  name = "${var.name_prefix}-db-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "5432"
    source_ips = [local.node1_cidr, local.node2_cidr]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = [local.bastion_cidr]
  }
}

resource "hcloud_server" "bastion" {
  name        = "${var.name_prefix}-bastion"
  image       = var.server_image
  server_type = var.servers.bastion.type
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
    egress_env      = []
    db_backup_age_private_key = ""
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
  server_type = var.servers.egress.type
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
    egress_env      = local.egress_env_lines
    db_backup_age_private_key = var.db_backup_age_private_key
  })

  labels = {
    project     = var.project
    environment = var.environment
    role        = "egress"
  }

  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_server" "node1" {
  name        = "${var.name_prefix}-node1"
  image       = var.server_image
  server_type = var.servers.node1.type
  location    = var.location

  public_net {
    ipv4_enabled = var.servers.node1.public_ipv4
    ipv6_enabled = var.servers.node1.public_ipv6
  }

  network {
    network_id = hcloud_network.main.id
    ip         = var.servers.node1.private_ip
  }

  ssh_keys           = local.ssh_key_ids
  firewall_ids       = [hcloud_firewall.node1.id]
  placement_group_id = local.pg_node1_id
  user_data = templatefile("${path.module}/templates/cloud-init.tftpl", {
    bootstrap_role  = "node1"
    bootstrap_url   = var.bootstrap_artifacts["node1"].url
    bootstrap_sha256 = var.bootstrap_artifacts["node1"].sha256
    db_volume_name  = var.db_volume.name
    db_volume_format = var.db_volume.format
    private_cidr    = var.private_cidr
    egress_env      = []
    db_backup_age_private_key = ""
  })

  labels = {
    project     = var.project
    environment = var.environment
    role        = "node1"
  }

  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_server" "node2" {
  name        = "${var.name_prefix}-node2"
  image       = var.server_image
  server_type = var.servers.node2.type
  location    = var.location

  public_net {
    ipv4_enabled = var.servers.node2.public_ipv4
    ipv6_enabled = var.servers.node2.public_ipv6
  }

  network {
    network_id = hcloud_network.main.id
    ip         = var.servers.node2.private_ip
  }

  ssh_keys           = local.ssh_key_ids
  firewall_ids       = [hcloud_firewall.node2.id]
  placement_group_id = local.pg_node2_id
  user_data = templatefile("${path.module}/templates/cloud-init.tftpl", {
    bootstrap_role  = "node2"
    bootstrap_url   = var.bootstrap_artifacts["node2"].url
    bootstrap_sha256 = var.bootstrap_artifacts["node2"].sha256
    db_volume_name  = var.db_volume.name
    db_volume_format = var.db_volume.format
    private_cidr    = var.private_cidr
    egress_env      = []
    db_backup_age_private_key = ""
  })

  labels = {
    project     = var.project
    environment = var.environment
    role        = "node2"
  }

  depends_on = [hcloud_network_subnet.main]
}

resource "hcloud_server" "db" {
  name        = "${var.name_prefix}-db"
  image       = var.server_image
  server_type = var.servers.db.type
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
    egress_env      = []
    db_backup_age_private_key = ""
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

resource "hcloud_load_balancer_target" "node1" {
  type             = "server"
  load_balancer_id = hcloud_load_balancer.main.id
  server_id        = hcloud_server.node1.id
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
