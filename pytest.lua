---
--- Generated by EmmyLua(https://github.com/EmmyLua)
--- Created by liaozhaoyan.
--- DateTime: 2023/11/9 2:49 PM
---

package.cpath = "./?.so"
local elfmap = require("elfmap")

local m = elfmap.new("/usr/local/cloudmonitor/bin/argusagent")
--local m = elfmap.new("/usr/bin/python2.7")
print(m:count())

for _, start, stop, symbol in m:maps() do
    print(string.format("symbol%s: 0x%x, 0x%x", symbol, start, stop))
end


