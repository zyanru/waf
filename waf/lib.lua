require 'config'

--Get the client IP
function get_client_ip()

    local real_ip = ngx.req.get_headers()["X_real_ip"]
    local remote_ip = ngx.var.remote_addr
    -- local CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"] 
    local CLIENT_IP = real_ip and realip or remote_ip

    return CLIENT_IP

end

--Get the Config IP
function get_conf_ip(rulefilename)

    local io = require 'io'
    local RULE_PATH = config_rule_dir
    local RULE_FILE = io.open(RULE_PATH..'/'..rulefilename,"r")
    if RULE_FILE == nil then
        return
    end
    local RULE_TABLE = {}
    for line in RULE_FILE:lines() do
        table.insert(RULE_TABLE,line)
    end
    RULE_FILE:close()

    return(RULE_TABLE)
end

--WAF log record for json,(use logstash codec => json)
function log_record(method,url,data,ruletag)
    local cjson = require("cjson")
    local io = require 'io'
    local LOG_PATH = config_log_path
    local CLIENT_IP = get_client_ip()
    local USER_AGENT = ngx.var.http_user_agent
    local SERVER_NAME = ngx.var.server_name
    local LOCAL_TIME = ngx.localtime()

    local log_json_obj = {
                 client_ip = CLIENT_IP,
                 local_time = LOCAL_TIME,
                 server_name = SERVER_NAME,
                 user_agent = USER_AGENT,
                 attack_method = method,
                 req_url = url,
                 req_data = data,
                 rule_tag = ruletag,
              }

    local LOG_LINE = cjson.encode(log_json_obj)
    local file = io.open(LOG_PATH,"a")
    if file == nil then
        return
    end
    file:write(LOG_LINE.."\n")
    file:flush()
    file:close()
end

-- 
function uri_checkin(t)
    local uri_rule

    if t == nil or t == "" then
        return uri_rule 
    end

    for _, item in pairs(t) do
        if item.uri == ngx.var.uri then
	     local uri = item.uri
	     local count = tonumber(string.match(item.rate,'(.*)/'))
	     local expiretime = tonumber(string.match(item.rate,'/(.*)'))
	     local blocktime = tonumber(item.blocktime)
	     local op = tonumber(item.op)
	     uri_rule = {
		    uri = uri,
                    count = count,
		    expiretime = expiretime,
		    blocktime = blocktime,
		    op = op
		}
             return uri_rule
        end
    end

    return uri_rule
end
