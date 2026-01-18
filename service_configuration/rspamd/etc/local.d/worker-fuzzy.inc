worker "fuzzy" {
  # Socket to listen on (UDP and TCP from rspamd 1.3)
  bind_socket = "*:11335";

  # Number of processes to serve this storage (useful for read scaling)
  count = 4;

  # Backend ("sqlite" or "redis" - default "sqlite")
  backend = "sqlite";

  # sqlite: Where data file is stored (must be owned by rspamd user)
  database = "${DBDIR}/fuzzy.db";

  # Hashes storage time (3 months)
  expire = 90d;

  # Synchronize updates to the storage each minute
  sync = 1min;
}

rule "HTML_ENABLED" {
  servers = "localhost:11335";
  algorithm = "mumhash";  # Used for HTML shingles too
  
  # Enable HTML structure fuzzy hashing
  html_shingles = true;
  
  # Minimum HTML tags (default: 10)
  # Lower values = more emails hashed, higher FP risk
  # Higher values = fewer emails, more unique structures
  min_html_tags = 15;
  
  # Weight multiplier for HTML matches (default: 1.0)
  html_weight = 1.0;
  
  # Text fuzzy can be enabled simultaneously
  text_shingles = true;
  min_length = 32;
  
  fuzzy_map = {
    FUZZY_HTML_SPAM {
      flag = 100;
      max_score = 20.0;
    }
  }
}

rule "BRAND_PROTECTION" {
  html_shingles = true;
  min_html_tags = 20;  # Brands use complex HTML
  html_weight = 1.5;   # Prioritize structure
  
  fuzzy_map = {
    FUZZY_LEGIT_BRANDS {
      flag = 1;
      max_score = 20.0;
    }
  }
}

rule "SPAM_CAMPAIGNS" {
  html_shingles = true;
  min_html_tags = 15;
  html_weight = 1.0;
  
  fuzzy_map = {
    FUZZY_SPAM_TEMPLATES {
      flag = 200;
      max_score = 15.0;
    }
  }
}
