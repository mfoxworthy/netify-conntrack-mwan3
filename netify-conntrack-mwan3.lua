#!/usr/bin/lua

local timeformat = '%a %b %d %H:%M:%S'

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E | grep NEW | grep \'tcp|udp\''
local pipeout = assert(io.popen(conncmd, 'w'))

while true do
    
    s = pipeout:write()
    words = {}
      for w in s:gmatch("%w+") do 
        table.insert(words, w) 
      end

--print (words [2]) --> is

    for k, v in ipairs (words) do
      print (v)
    end -- for
    -- pipeout:write()
    pipeout:flush()
    
   
end

pipeout:close()