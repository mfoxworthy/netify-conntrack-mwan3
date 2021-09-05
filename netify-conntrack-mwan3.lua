#!/usr/bin/lua

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E'
local pipeout  = assert(io.popen(conncmd,  'w'))

while true do
    
  pipeout:write()
  pipeout:flush()
  
end
      
pipeout:close()