#!/usr/bin/lua

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E | grep \'tcp|udp\''
local pipeout  = assert(io.popen(conncmd,  'w'))

while true do
    
  print(pipeout:read())
  pipeout:flush()
end
      
pipeout:close()