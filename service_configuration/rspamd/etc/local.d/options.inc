# Local networks - Rspamd trust configuration

local_addrs = [
  # Localhost
  "127.0.0.0/8",
  "::1",
];

# DNS configuration
dns {
  # Use Unbound on localhost (from Part 1)
  nameserver = ["127.0.0.1:53"];
  
  # Enable DNSSEC validation
  enable_dnssec = true;
}


neighbours {
    # Názvy serverů (zobrazí se v UI)
    mail {
        host = "http://hostname1:11334";
        path = "/";
    }
    mail2 {
        host = "http://hostname2:11334";
    }
}

