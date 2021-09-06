#!/usr/bin/lua

-- Lua doesn't have a built in sleep funtion so we build are own.

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
        -- nothing
    end
end

-- Function to split the conntrack string and put it into a table -- Tables can be arrays in Lua

function split (line)
  words = {}
  for w in line:gmatch("%S+") do 
    table.insert(words, w)
  end
  return words  
end

-- Function to reset flow

function reset (dst_IP)
  local reset = "conntrack -D -d " .. dst_IP
  os.execute(reset)  
end

-- Function to get iptables rules

function fetchpolicy ()
  local polcmd = 'iptables -L mwan3_rules -t mangle | grep -v LOG | grep match-set | awk \'{print $1}\''
  local getpols = assert(io.popen(polcmd, 'r'))
  pols = {}
  for policy in getpols:lines() do
    table.insert(pols, policy)
  end
  getpols:flush()
  getpols:close()
  return pols
end

function fetchipsets ()
  local ipsetcmd = 'iptables -L mwan3_rules -t mangle | grep -v LOG | grep match-set | awk \'{print $7}\''
  local getsets = assert(io.popen(ipsetcmd, 'r'))
  sets = {}
  for set in getsets:lines() do
    table.insert(sets, set)
  end
  getsets:flush()
  getsets:close()
  return sets
end

  
function fetchmarks (policy, ipsets)
  marks = {}
  for i, v in ipairs(policy) do
    k = ipsets[i]
    local markcmd = assert(io.popen('iptables -L ' .. v .. ' -t mangle | grep MARK | awk \'{print $16}\' | cut -c -5'), 'r')
      for m in markcmd:lines() do
        marks[tonumber(m, 10)] = k
      end
    markcmd:flush()
    markcmd:close()
  end
  return marks
end

function testconntrack (f_mark, dst_IP, g_marks)
  local conn_reset = 0
  print(f_mark)
  print(dst_IP)
  if (f_mark ~= nil)
    then
      sleep(1)
      for k, v in pairs(g_marks) do
        local conncheckcmd = 'ipset list ' .. v .. ' | grep timeout | grep -v Header | awk \'{print $1}\''
        print('Checking set ' .. v)
        local conncheck = assert(io.popen(conncheckcmd, 'r'))
          for m in conncheck:lines() do
              if ( m == dst_IP )
                then
                  print('Found in set ' .. v .. " " .. k)
                  in_table = k
              
              end
          end
      end
  end
  if (in_table == nil)
    then
      print('Not in sets')
  elseif (in_table ~= tonumber(f_mark)
    then
      print('Found in wrong set ' .. f_mark .. " " .. in_table)
      conn_reset = 1
  end
  return conn_reset
end

function pipeconntrack (marks)

  -- Variables to to pipe conntrack data into our script. 
  -- We don't format it on the line, we use multiple variables
  -- so its best to just use Lua.
  
  local conncmd = 'conntrack -E'
  local pipein  = assert(io.popen(conncmd,  'r'))

  for line in pipein:lines() do
    conn_arr = split(line)
    
    if (conn_arr [1] ~= nil)
      then
        status = string.gsub(conn_arr [1], "%A", "")
    
    -- We need to know if the NEW connection is TCP or UDP.
    -- conntrack formats these lines differently
    
        if (status == "NEW" and conn_arr [2] == "tcp")
           then
            local dst_IP = string.gsub(conn_arr [7], "dst%=", "")
            local f_mark = string.gsub(conn_arr [15], "mark%=", "")
            local test_reset = testconntrack(f_mark, dst_IP, marks)
            if (test_reset == 1)
              then
                reset(dst_IP)
            end
            print(test_reset)
            -- print("tcp flow ", dst_IP)
            --reset(dst_IP)
        elseif (status == "NEW" and conn_arr [2] == "udp") -- pick off UDP
            then
              if (string.gsub(conn_arr [8], "dport%=", "") ~= ("53" or "68" or "67"))
                then
                  dport = string.gsub(conn_arr [8], "dport%=", "")
                  dst_IP = string.gsub(conn_arr [6], "dst%=", "")
                  
                  -- print("udp flow ", dst_IP, " ", dport)
                  
              end
        end
    end
    pipein:flush()    
  end
  
end


policy = fetchpolicy()
ipsets = fetchipsets()
marks = fetchmarks(policy, ipsets)
for i,v in ipairs(policy) do print(v) end
for k,v in pairs(marks) do print(k, v) end


pipeconntrack(marks)
pipein:close()
