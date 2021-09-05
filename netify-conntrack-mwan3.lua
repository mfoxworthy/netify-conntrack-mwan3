#!/usr/bin/lua

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E | grep \'tcp|udp\''
--local pipeout = assert(io.popen(conncmd, 'w'))
local pipein  = assert(io.popen(conncmd,  'r'))

while true do
    
    for line in pipein:lines() do
      local words = {}
      print(line)
        for w in line:gmatch("%w+") do 
          table.insert(words, w) 
        end

      print (words [2]) --> is
      
      for k, v in ipairs (words) do
        print (v)
      end -- for
      
    end
    
end

pipein:close()