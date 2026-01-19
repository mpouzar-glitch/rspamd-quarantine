# Milter worker configuration

# Bind to localhost TCP port 11332
bind_socket = "127.0.0.1:11332";

# Enable milter protocol
milter = yes;

# Timeout for connections
timeout = 120s;

# Upstream configuration (scan locally)
upstream "local" {
  default = yes;
  self_scan = yes;
}
