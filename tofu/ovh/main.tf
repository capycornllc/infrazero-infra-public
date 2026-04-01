provider "ovh" {
  endpoint           = "ovh-eu"
  application_key    = var.ovh_application_key
  application_secret = var.ovh_application_secret
  consumer_key       = var.ovh_consumer_key
}

provider "openstack" {
  auth_url    = var.openstack_auth_url
  user_name   = var.openstack_user_name
  password    = var.openstack_password
  tenant_id   = var.openstack_tenant_id
  region      = var.location
}

# ------------------------------------------------------------------ #
#  Data: image lookup                                                  #
# ------------------------------------------------------------------ #

data "openstack_images_image_v2" "ubuntu" {
  name        = var.server_image
  most_recent = true
}

# ------------------------------------------------------------------ #
#  Network                                                             #
# ------------------------------------------------------------------ #

resource "openstack_networking_network_v2" "main" {
  name           = "${var.name_prefix}-net"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "main" {
  name       = "${var.name_prefix}-subnet"
  network_id = openstack_networking_network_v2.main.id
  cidr       = var.private_cidr
  ip_version = 4

  allocation_pool {
    start = cidrhost(var.private_cidr, 100)
    end   = cidrhost(var.private_cidr, 200)
  }

  dns_nameservers = ["213.186.33.99", "1.1.1.1"]
}

resource "openstack_networking_router_v2" "main" {
  name                = "${var.name_prefix}-router"
  admin_state_up      = true
  external_network_id = data.openstack_networking_network_v2.ext_net.id
}

data "openstack_networking_network_v2" "ext_net" {
  name = "Ext-Net"
}

resource "openstack_networking_router_interface_v2" "main" {
  router_id = openstack_networking_router_v2.main.id
  subnet_id = openstack_networking_subnet_v2.main.id
}

# ------------------------------------------------------------------ #
#  SSH Key                                                             #
# ------------------------------------------------------------------ #

resource "openstack_compute_keypair_v2" "ops" {
  for_each   = local.ssh_keys_map
  name       = "${var.name_prefix}-ops-${each.key}"
  public_key = each.value
}

# ------------------------------------------------------------------ #
#  Security Groups (equivalent to Hetzner firewalls)                   #
# ------------------------------------------------------------------ #

resource "openstack_networking_secgroup_v2" "bastion" {
  name        = "${var.name_prefix}-bastion-sg"
  description = "Bastion security group"
}

resource "openstack_networking_secgroup_rule_v2" "bastion_wg" {
  count             = var.wireguard.enabled ? 1 : 0
  security_group_id = openstack_networking_secgroup_v2.bastion.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = var.wireguard.listen_port
  port_range_max    = var.wireguard.listen_port
  remote_ip_prefix  = "0.0.0.0/0"
}

resource "openstack_networking_secgroup_rule_v2" "bastion_private_tcp" {
  security_group_id = openstack_networking_secgroup_v2.bastion.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  remote_ip_prefix  = var.private_cidr
}

resource "openstack_networking_secgroup_rule_v2" "bastion_private_udp" {
  security_group_id = openstack_networking_secgroup_v2.bastion.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  remote_ip_prefix  = var.private_cidr
}

resource "openstack_networking_secgroup_rule_v2" "bastion_private_icmp" {
  security_group_id = openstack_networking_secgroup_v2.bastion.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = var.private_cidr
}

resource "openstack_networking_secgroup_rule_v2" "bastion_ssh" {
  for_each          = toset(local.bastion_ssh_cidrs)
  security_group_id = openstack_networking_secgroup_v2.bastion.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_v2" "egress" {
  name        = "${var.name_prefix}-egress-sg"
  description = "Egress security group"
}

resource "openstack_networking_secgroup_rule_v2" "egress_http" {
  for_each          = toset(local.egress_service_cidrs)
  security_group_id = openstack_networking_secgroup_v2.egress.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "egress_https" {
  for_each          = toset(local.egress_service_cidrs)
  security_group_id = openstack_networking_secgroup_v2.egress.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "egress_ssh" {
  security_group_id = openstack_networking_secgroup_v2.egress.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = local.bastion_cidr
}

resource "openstack_networking_secgroup_v2" "k3s" {
  name        = "${var.name_prefix}-k3s-sg"
  description = "K3s nodes security group"
}

resource "openstack_networking_secgroup_rule_v2" "k3s_api" {
  for_each          = toset(concat(var.wireguard.allowed_cidrs, [local.bastion_cidr, local.egress_cidr], local.k3s_node_cidrs))
  security_group_id = openstack_networking_secgroup_v2.k3s.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 6443
  port_range_max    = 6443
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "k3s_vxlan" {
  for_each          = toset(local.k3s_node_cidrs)
  security_group_id = openstack_networking_secgroup_v2.k3s.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 8472
  port_range_max    = 8472
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "k3s_kubelet" {
  for_each          = toset(local.k3s_control_plane_cidrs)
  security_group_id = openstack_networking_secgroup_v2.k3s.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 10250
  port_range_max    = 10250
  remote_ip_prefix  = each.value
}

# etcd: K3s control planes + DB nodes (Patroni uses embedded etcd)
resource "openstack_networking_secgroup_rule_v2" "k3s_etcd" {
  for_each          = local.k3s_ha_enabled ? toset(concat(local.k3s_control_plane_cidrs, [local.db_cidr], local.db_replica_cidrs)) : toset([])
  security_group_id = openstack_networking_secgroup_v2.k3s.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 2379
  port_range_max    = 2380
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "k3s_ssh" {
  for_each          = toset(concat(var.wireguard.allowed_cidrs, [local.bastion_cidr]))
  security_group_id = openstack_networking_secgroup_v2.k3s.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "k3s_lb_ports" {
  for_each          = local.k3s_lb_ports
  security_group_id = openstack_networking_secgroup_v2.k3s.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = tonumber(each.value)
  port_range_max    = tonumber(each.value)
  remote_ip_prefix  = var.private_cidr
}

resource "openstack_networking_secgroup_v2" "db" {
  name        = "${var.name_prefix}-db-sg"
  description = "Database security group"
}

resource "openstack_networking_secgroup_rule_v2" "db_postgres" {
  for_each          = toset(concat(local.k3s_node_cidrs, local.db_replica_cidrs, local.pgbouncer_enabled ? [local.pgbouncer_cidr] : []))
  security_group_id = openstack_networking_secgroup_v2.db.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5432
  port_range_max    = 5432
  remote_ip_prefix  = each.value
}

# Patroni REST API (8008) — between DB nodes and pgbouncer callback
resource "openstack_networking_secgroup_rule_v2" "db_patroni_api" {
  for_each          = toset(concat(local.db_replica_cidrs, [local.db_cidr], local.pgbouncer_enabled ? [local.pgbouncer_cidr] : []))
  security_group_id = openstack_networking_secgroup_v2.db.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8008
  port_range_max    = 8008
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "db_ssh" {
  for_each          = toset(concat(var.wireguard.allowed_cidrs, [local.bastion_cidr]))
  security_group_id = openstack_networking_secgroup_v2.db.id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
}

# ------------------------------------------------------------------ #
#  Servers                                                             #
# ------------------------------------------------------------------ #

resource "openstack_compute_instance_v2" "bastion" {
  name            = "${var.name_prefix}-bastion"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.bastion_server_type
  key_pair        = openstack_compute_keypair_v2.ops["0"].name
  security_groups = [openstack_networking_secgroup_v2.bastion.name]
  user_data       = local.cloud_init_rendered_bastion

  network {
    uuid        = openstack_networking_network_v2.main.id
    fixed_ip_v4 = var.servers.bastion.private_ip
  }

  lifecycle {
    ignore_changes = [user_data]
  }

  metadata = {
    project     = var.project
    environment = var.environment
    role        = "bastion"
  }

  depends_on = [openstack_networking_subnet_v2.main, openstack_networking_router_interface_v2.main]
}

resource "openstack_compute_instance_v2" "egress" {
  name            = "${var.name_prefix}-egress"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.egress_server_type
  key_pair        = openstack_compute_keypair_v2.ops["0"].name
  security_groups = [openstack_networking_secgroup_v2.egress.name]
  user_data       = local.cloud_init_rendered_egress

  network {
    uuid        = openstack_networking_network_v2.main.id
    fixed_ip_v4 = var.servers.egress.private_ip
  }

  lifecycle {
    ignore_changes = [user_data]
  }

  metadata = {
    project     = var.project
    environment = var.environment
    role        = "egress"
  }

  depends_on = [openstack_networking_subnet_v2.main, openstack_networking_router_interface_v2.main]
}

resource "openstack_compute_instance_v2" "k3s" {
  for_each = local.k3s_nodes_map

  name            = "${var.name_prefix}-node${tonumber(each.key) + 1}"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.k3s_node_server_type
  key_pair        = openstack_compute_keypair_v2.ops["0"].name
  security_groups = [openstack_networking_secgroup_v2.k3s.name]
  user_data       = local.cloud_init_rendered_k3s[each.key]

  network {
    uuid        = openstack_networking_network_v2.main.id
    fixed_ip_v4 = each.value.private_ip
  }

  lifecycle {
    ignore_changes = [user_data]
  }

  metadata = {
    project     = var.project
    environment = var.environment
    role        = each.key == local.k3s_server_key ? "node1" : "node${tonumber(each.key) + 1}"
    k3s_role    = tonumber(each.key) < local.k3s_control_planes_count ? "server" : "agent"
  }

  depends_on = [openstack_networking_subnet_v2.main, openstack_networking_router_interface_v2.main]
}

resource "openstack_compute_instance_v2" "db" {
  name            = "${var.name_prefix}-db"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.db_server_type
  key_pair        = openstack_compute_keypair_v2.ops["0"].name
  security_groups = [openstack_networking_secgroup_v2.db.name]
  user_data       = local.cloud_init_rendered_db

  network {
    uuid        = openstack_networking_network_v2.main.id
    fixed_ip_v4 = var.servers.db.private_ip
  }

  lifecycle {
    ignore_changes = [user_data]
  }

  metadata = {
    project     = var.project
    environment = var.environment
    role        = "db"
  }

  depends_on = [openstack_networking_subnet_v2.main, openstack_networking_router_interface_v2.main]
}

# ------------------------------------------------------------------ #
#  Block Storage Volume (DB)                                           #
# ------------------------------------------------------------------ #

resource "openstack_blockstorage_volume_v3" "db" {
  name = var.db_volume.name
  size = var.db_volume.size

  lifecycle {
    prevent_destroy = true
  }

  metadata = {
    project     = var.project
    environment = var.environment
  }
}

resource "openstack_compute_volume_attach_v2" "db" {
  instance_id = openstack_compute_instance_v2.db.id
  volume_id   = openstack_blockstorage_volume_v3.db.id
}

# ------------------------------------------------------------------ #
#  DB Replica Security Group + Instances                               #
# ------------------------------------------------------------------ #

resource "openstack_networking_secgroup_v2" "db_replica" {
  count       = length(var.db_replicas) > 0 ? 1 : 0
  name        = "${var.name_prefix}-db-replica-sg"
  description = "Database replica security group"
}

resource "openstack_networking_secgroup_rule_v2" "db_replica_postgres" {
  for_each          = length(var.db_replicas) > 0 ? toset(concat(local.k3s_node_cidrs, [local.db_cidr], local.pgbouncer_enabled ? [local.pgbouncer_cidr] : [])) : toset([])
  security_group_id = openstack_networking_secgroup_v2.db_replica[0].id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5432
  port_range_max    = 5432
  remote_ip_prefix  = each.value
}

# Patroni REST API (8008) — between DB replica nodes and pgbouncer callback
resource "openstack_networking_secgroup_rule_v2" "db_replica_patroni_api" {
  for_each          = length(var.db_replicas) > 0 ? toset(concat(local.db_replica_cidrs, [local.db_cidr], local.pgbouncer_enabled ? [local.pgbouncer_cidr] : [])) : toset([])
  security_group_id = openstack_networking_secgroup_v2.db_replica[0].id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8008
  port_range_max    = 8008
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "db_replica_ssh" {
  for_each          = length(var.db_replicas) > 0 ? toset(concat(var.wireguard.allowed_cidrs, [local.bastion_cidr])) : toset([])
  security_group_id = openstack_networking_secgroup_v2.db_replica[0].id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
}

resource "openstack_compute_instance_v2" "db_replica" {
  for_each = local.db_replicas_map

  name            = "${var.name_prefix}-db-replica-${tonumber(each.key) + 1}"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.db_server_type
  key_pair        = openstack_compute_keypair_v2.ops["0"].name
  security_groups = [openstack_networking_secgroup_v2.db_replica[0].name]
  user_data       = local.cloud_init_rendered_db_replica

  network {
    uuid        = openstack_networking_network_v2.main.id
    fixed_ip_v4 = each.value.private_ip
  }

  lifecycle {
    ignore_changes = [user_data]
  }

  metadata = {
    project     = var.project
    environment = var.environment
    role        = "db-replica"
    replica_idx = each.key
  }

  depends_on = [openstack_networking_subnet_v2.main, openstack_networking_router_interface_v2.main]
}

# ------------------------------------------------------------------ #
#  PgBouncer Security Group + Instance                                 #
# ------------------------------------------------------------------ #

resource "openstack_networking_secgroup_v2" "pgbouncer" {
  count       = local.pgbouncer_enabled ? 1 : 0
  name        = "${var.name_prefix}-pgbouncer-sg"
  description = "PgBouncer connection pooler security group"
}

# Write pool (5432) and read pool (5433) from K3s nodes
resource "openstack_networking_secgroup_rule_v2" "pgbouncer_pools" {
  for_each          = local.pgbouncer_enabled ? toset(local.k3s_node_cidrs) : toset([])
  security_group_id = openstack_networking_secgroup_v2.pgbouncer[0].id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5432
  port_range_max    = 5433
  remote_ip_prefix  = each.value
}

resource "openstack_networking_secgroup_rule_v2" "pgbouncer_ssh" {
  for_each          = local.pgbouncer_enabled ? toset(concat(var.wireguard.allowed_cidrs, [local.bastion_cidr])) : toset([])
  security_group_id = openstack_networking_secgroup_v2.pgbouncer[0].id
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = each.value
}

resource "openstack_compute_instance_v2" "pgbouncer" {
  count           = local.pgbouncer_enabled ? 1 : 0
  name            = "${var.name_prefix}-pgbouncer"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.pgbouncer_server_type
  key_pair        = openstack_compute_keypair_v2.ops["0"].name
  security_groups = [openstack_networking_secgroup_v2.pgbouncer[0].name]
  user_data       = local.cloud_init_rendered_pgbouncer

  network {
    uuid        = openstack_networking_network_v2.main.id
    fixed_ip_v4 = try(var.servers.pgbouncer.private_ip, "")
  }

  lifecycle {
    ignore_changes = [user_data]
  }

  metadata = {
    project     = var.project
    environment = var.environment
    role        = "pgbouncer"
  }

  depends_on = [openstack_networking_subnet_v2.main, openstack_networking_router_interface_v2.main]
}

# ------------------------------------------------------------------ #
#  Load Balancer (Octavia)                                             #
# ------------------------------------------------------------------ #

resource "openstack_lb_loadbalancer_v2" "main" {
  name          = "${var.name_prefix}-lb"
  vip_subnet_id = openstack_networking_subnet_v2.main.id
  vip_address   = local.lb_private_ip
}

resource "openstack_lb_listener_v2" "http" {
  name            = "${var.name_prefix}-http"
  loadbalancer_id = openstack_lb_loadbalancer_v2.main.id
  protocol        = "TCP"
  protocol_port   = local.lb_services["http"].listen_port
}

resource "openstack_lb_pool_v2" "http" {
  name        = "${var.name_prefix}-http-pool"
  listener_id = openstack_lb_listener_v2.http.id
  protocol    = "TCP"
  lb_method   = "ROUND_ROBIN"
}

resource "openstack_lb_member_v2" "http" {
  for_each      = local.k3s_nodes_map
  pool_id       = openstack_lb_pool_v2.http.id
  address       = each.value.private_ip
  protocol_port = local.lb_services["http"].destination_port
  subnet_id     = openstack_networking_subnet_v2.main.id
}

resource "openstack_lb_monitor_v2" "http" {
  pool_id     = openstack_lb_pool_v2.http.id
  type        = "TCP"
  delay       = var.load_balancer.health_check.interval
  timeout     = var.load_balancer.health_check.timeout
  max_retries = var.load_balancer.health_check.retries
}

resource "openstack_lb_listener_v2" "https" {
  name            = "${var.name_prefix}-https"
  loadbalancer_id = openstack_lb_loadbalancer_v2.main.id
  protocol        = "TCP"
  protocol_port   = local.lb_services["https"].listen_port
}

resource "openstack_lb_pool_v2" "https" {
  name        = "${var.name_prefix}-https-pool"
  listener_id = openstack_lb_listener_v2.https.id
  protocol    = "TCP"
  lb_method   = "ROUND_ROBIN"
}

resource "openstack_lb_member_v2" "https" {
  for_each      = local.k3s_nodes_map
  pool_id       = openstack_lb_pool_v2.https.id
  address       = each.value.private_ip
  protocol_port = local.lb_services["https"].destination_port
  subnet_id     = openstack_networking_subnet_v2.main.id
}

resource "openstack_lb_monitor_v2" "https" {
  pool_id     = openstack_lb_pool_v2.https.id
  type        = "TCP"
  delay       = var.load_balancer.health_check.interval
  timeout     = var.load_balancer.health_check.timeout
  max_retries = var.load_balancer.health_check.retries
}

# ------------------------------------------------------------------ #
#  Floating IPs (public access)                                        #
# ------------------------------------------------------------------ #

resource "openstack_networking_floatingip_v2" "bastion" {
  pool = "Ext-Net"
}

resource "openstack_compute_floatingip_associate_v2" "bastion" {
  floating_ip = openstack_networking_floatingip_v2.bastion.address
  instance_id = openstack_compute_instance_v2.bastion.id
}

resource "openstack_networking_floatingip_v2" "egress" {
  pool = "Ext-Net"
}

resource "openstack_compute_floatingip_associate_v2" "egress" {
  floating_ip = openstack_networking_floatingip_v2.egress.address
  instance_id = openstack_compute_instance_v2.egress.id
}

resource "openstack_networking_floatingip_v2" "lb" {
  pool    = "Ext-Net"
  port_id = openstack_lb_loadbalancer_v2.main.vip_port_id
}
