#!/usr/bin/lua

local timeformat = '%a %b %d %H:%M:%S'

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

local conncmd = 'conntrack -E | grep NEW | grep \'tcp|udp\''
--local pipeout = assert(io.popen(conncmd, 'w'))
local pipein  = assert(io.popen(conncmd,  'r'))

while true do
    
    for line in pipein:lines() do
    words = {}
      for w in line:gmatch("%w+") do 
        table.insert(words, w) 
      end

--print (words [2]) --> is

    for k, v in ipairs (words) do
      print (v)
    end -- for
    
   
end

pipein:close()