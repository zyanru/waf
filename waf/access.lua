require 'init'

local function waf_main()

    if white_ip_check() then
    elseif black_ip_check() then
    elseif cc_rate_limit() then
    else 
	return
    end

end

waf_main()
