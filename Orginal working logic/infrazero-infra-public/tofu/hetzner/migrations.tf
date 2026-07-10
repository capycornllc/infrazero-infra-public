moved {
  from = hcloud_load_balancer_target.k3s_server
  to   = hcloud_load_balancer_target.k3s["0"]
}

