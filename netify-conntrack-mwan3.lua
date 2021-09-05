#!/usr/bin/lua

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E | grep \'tcp|udp\''
local pipein  = assert(io.popen(conncmd,  'r'))

while true do
    
    line = pipein:read()
      
    print(line)
    pipein:flush()
      
    
    
end

pipein:close()