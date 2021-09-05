#!/usr/bin/lua

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E'
local pipein  = assert(io.popen(conncmd,  'r'))

for line in pipein:lines() do
    
  print(line)
  pipein:flush()
  
end
      
pipein:close()