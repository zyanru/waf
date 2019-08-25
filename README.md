# waf

学习[lua-nginx-module](https://github.com/openresty/lua-nginx-module)，参考并引用了 <https://github.com/unixhot/waf> 部分代码

## 功能描述

CC 简单防御:
- IP黑白名单控制
- 根据URI限制策略(例如：uri='/api/', rate='12/20', blocktime=600, op=1. 某IP ，'/api/' 页面如果在统计时间窗口20秒内被访问超过了12次，则封禁5分钟.)，限制单IP请求频率

## 部署配置

### 1. 安装OpenResty 或者 Nginx重新编译支持LUA

```
$ sudo mkdir -p /etc/nginx/lua_scripts/
$ sudo mkdir /var/log/nginx
$ git clone https://github.com/zyanru/waf.git
$ sudo cp -a waf/waf /etc/nginx/lua_scripts/
```

### 2. 配置nginx.conf

```
lua_shared_dict cclimit 50m;
lua_package_path "/etc/nginx/lua_scripts/waf/?.lua;;";
init_by_lua_file "/etc/nginx/lua_scripts/waf/init.lua";
access_by_lua_file "/etc/nginx/lua_scripts/waf/access.lua";
```

### 3. 编辑/etc/nginx/lua_scripts/waf/config.lua 按例配置相关规则
