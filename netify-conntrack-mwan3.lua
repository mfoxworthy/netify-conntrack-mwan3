#!/usr/bin/lua

local timeformat = '%a %b %d %H:%M:%S'

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E | grep NEW | grep tcp | awk \'{print $7}\' | cut -c 5-'
local pipeout = assert(io.popen(conncmd, 'w'))

while true do
    
    pipeout:write()
    pipeout:flush()
    
   
end

pipeout:close()