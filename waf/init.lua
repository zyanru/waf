require 'config'
require 'lib'

-- Allow white ip
function white_ip_check()
    if config_white_ip_check == "on" then
        local IP_WHITE_RULE = get_conf_ip('whiteip.rule')
        local WHITE_IP = get_client_ip()
        if IP_WHITE_RULE ~= nil then
            for _,rule in pairs(IP_WHITE_RULE) do
                if rule ~= "" and ngx.re.find(WHITE_IP,rule,"jo") then
                    log_record('WhiteIP',ngx.var.uri,"_","_")
                    return true
                end
            end
        end
    end
end

-- Deny black ip
function black_ip_check()
     if config_black_ip_check == "on" then
        local IP_BLACK_RULE = get_conf_ip('blackip.rule')
        local BLACK_IP = get_client_ip()
        if IP_BLACK_RULE ~= nil then
            for _,rule in pairs(IP_BLACK_RULE) do
                if rule ~= "" and ngx.re.find(BLACK_IP,rule,"jo") then
                    log_record('BlackIP',ngx.var.uri,"_","_")
                    if waf.action == "1" then
                        ngx.exit(403)
                        return true
                    end
                end
            end
        end
    end
end

-- Anti CC attack
function cc_rate_limit()

    local limit = ngx.shared.cclimit
    local realip = get_client_ip()	
    local key = ngx.var.host .. ngx.var.uri .. realip
    local req = limit:get(key)
    local uri_rule_info = uri_checkin(config_url_limit)
 
    if nil == uri_rule_info then
        if nil == req then
            limit:set(key, 1, 60)
        else
	    limit:incr(key, 1)
        end     
	log_record('uri_rate not match', ngx.var.uri, req, 0)
        return
    end 

    local count = uri_rule_info.count
    local expiretime = uri_rule_info.expiretime
    local blocktime = uri_rule_info.blocktime
    local op = uri_rule_info.op

    if nil == req then
        limit:set(key, 1, expiretime)
    elseif req > 0 and req < count then
        limit:incr(key, 1)
    elseif req >= count then
        limit:set(key, -1, blocktime)
    end

    if req ~= nil and op == 1
    then
        if req < 0 then
            log_record('uri_rate blocked', ngx.var.uri, req, op)
            ngx.exit(403)
            return
        end
    else
        log_record('uri_rate', ngx.var.uri, req, op)
    end
        
    return false

end
