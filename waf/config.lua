--rule setting
waf = {action = "1"}

config_rule_dir = "/etc/nginx/lua_scripts/waf/conf"
config_log_path = "/var/log/nginx/waf.log"

--enable/disable white ip
config_white_ip_check = "on"

--enable/disable block ip
config_black_ip_check = "on"

-- op=1,block; op=2,log
config_url_limit = {
  {uri='/abc/', rate='10/15', blocktime=600, op=1},
  {uri='/api/', rate='12/20', blocktime=600, op=1}
}
