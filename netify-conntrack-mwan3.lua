#!/usr/bin/lua

-- Author - Michael Foxworthy

-- This program will keep track of connections on load balanced policies with mwan3.
-- The flows are detected with the Netify plugins and the ipset sets are updated wit the dst_IP
-- If the intended interface isn't used, this program will terminate the connection and delete
-- the entries from the ipsets. It will add the entry to the correct ipset rule. The next time
-- the connection is tried it will take the correct path.

-- Lua doesn't have a built in sleep funtion so we build are own. Still figuring out if this is useful.

function sleep (n)
    local t = os.clock()
    while os.clock() - t <= n do
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

function flow_reset (dst_IP, set, del_set)
  local reset = "conntrack -D -d " .. dst_IP
  os.execute('ipset del -exist ' .. del_set .. ' ' .. dst_IP)
  os.execute('ipset add -exist ' .. set .. ' ' .. dst_IP)
  sleep(1)
  os.execute(reset)
  os.execute('logger -p notice -t conntrack_fix \'Made ipset correction for \'' .. dst_IP)
end

-- Function to get iptables policy chain used by mwan3 for hooks

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

-- Funtion that fetches the rules from iptables -- Helper to figure out the ipsets mwan3 puts in.
-- We could have grabbed them from Netify configs but we wouldn't know the mark

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

-- Funtion to get marks from policies.

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

-- Heavy lifter funtion to test all flows then call the reset helper that resets flows and add the ip to the correct set.
-- If we have bugs, this is where we will find them :)

function fixconntrack (f_mark, dst_IP, g_marks)
  local conn_reset = 0
  local f_mark = tonumber(f_mark)
  mark_check = 0 -- There are more marks than those used for ipsets. We don't want false positives
  set_count = 0
  if (f_mark ~= nil)
    then
      -- sleep(1)
      for k, v in pairs(g_marks) do
        if (f_mark ~= k)
          then
            mark_check = mark_check + 1
        end
        set_count = set_count + 1
        local conncheckcmd = 'ipset list ' .. v .. ' | tail -n +9'
        if (logging == 1)
          then
            os.execute('logger -p notice -t conntrack_fix \'Checking set \'' .. v)
        end
        local conncheck = assert(io.popen(conncheckcmd, 'r'))
          for m in conncheck:lines() do
              if ( m == dst_IP )
                then
                  if (logging == 1)
                    then
                      os.execute('logger -p notice -t conntrack_fix \'Found in set \'' .. v .. " " .. k)
                  end
                  in_table = k
              end
          end
      end
  end
  if (in_table == nil)
    then
  elseif (mark_check == set_count)
    then
  elseif (in_table ~= f_mark)
    then
      local set = g_marks[f_mark]
      local del_set = g_marks[in_table]
      flow_reset(dst_IP, set, del_set)
      
      
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
            os.execute('logger -p notice -t conntrack_fix \"New flow detected\" ' .. dst_IP)
            if (f_mark == nil) -- need to figure out the empty ones but for now we'll ride through it.
              then
                os.execute('logger -p err -t conntrack_fix \"No tag found\"')
            else
              local f_mark = string.gsub(conn_arr [15], "mark%=", "")
            end
            
              
            local test_reset = fixconntrack(f_mark, dst_IP, marks)
        elseif (status == "NEW" and conn_arr [2] == "udp") -- pick off UDP
            then
              if (string.gsub(conn_arr [8], "dport%=", "") ~= ("53" or "68" or "67"))
                then
                  dport = string.gsub(conn_arr [8], "dport%=", "")
                  dst_IP = string.gsub(conn_arr [6], "dst%=", "")                  
              end
        end
    end
    pipein:flush()    
  end
  
end

-- Set tables up at start so we don't keep looking at static data.
logging = 1
policy = fetchpolicy()
ipsets = fetchipsets()
marks = fetchmarks(policy, ipsets)

-- Kick things off.

pipeconntrack(marks)

-- Close it all down

pipein:close()
