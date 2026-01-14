local lfs = require('lfs')

local function sha1(input)
  local b = bit32
  local band, bor, bxor, bnot, lrot, lsh = b.band, b.bor, b.bxor, b.bnot, b.lrotate, b.lshift
  local h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
  local function tf(chunk)
    local w = {}
    for j = 0, 15 do
      local c1, c2, c3, c4 = chunk:byte(j*4 + 1, j*4 + 4)
      w[j] = bor(lsh(c1, 24), lsh(c2, 16), lsh(c3, 8), c4)
    end
    for j = 16, 79 do
      w[j] = lrot(bxor(w[j-3], w[j-8], w[j-14], w[j-16]), 1)
    end
    local a, b, c, d, e = h0, h1, h2, h3, h4
    for j = 0, 79 do
      local f, k
      if j < 20 then
        f, k = bor(band(b, c), band(bnot(b), d)), 0x5A827999
      elseif j < 40 then
        f, k = bxor(b, c, d), 0x6ED9EBA1
      elseif j < 60 then
        f, k = bor(band(b, c), band(b, d), band(c, d)), 0x8F1BBCDC
      else
        f, k = bxor(b, c, d), 0xCA62C1D6
      end
      local t = (lrot(a, 5) + f + e + k + w[j]) % 4294967296
      a, b, c, d, e = t, a, lrot(b, 30), c, d
    end
    h0, h1, h2, h3, h4 = (h0+a)%4294967296, (h1+b)%4294967296, (h2+c)%4294967296, (h3+d)%4294967296, (h4+e)%4294967296
  end
  local buf, t_len = "", 0
  local f = type(input) == "string" and function() local r=input; input=nil; return r end or input
  while true do
    local c = f()
    if not c then break end
    buf = buf .. c
    t_len = t_len + #c
    while #buf >= 64 do
      tf(buf:sub(1, 64))
      buf = buf:sub(65)
    end
  end
  local bits = t_len * 8
  buf = buf .. "\128"
  if #buf > 56 then
    tf(buf .. string.rep("\0", 64 - #buf))
    buf = ""
  end
  buf = buf .. string.rep("\0", 56 - #buf)
  local ls = ""
  for i = 7, 0, -1 do
    ls = ls .. string.char(band(math.floor(bits / 256^i), 0xFF))
  end
  tf(buf .. ls)
  return string.format("%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4)
end

local function compress(data)
  if #data == 0 then return "" end
  local dict = {}
  for i = 0, 255 do dict[string.char(i)] = i end
  local res, w, dict_size = {}, "", 256
  for i = 1, #data do
    local c = data:sub(i, i)
    local wc = w .. c
    if dict[wc] then
      w = wc
    else
      local code = dict[w]
      table.insert(res, string.char(math.floor(code / 256), code % 256))
      if dict_size < 65535 then
        dict[wc] = dict_size
        dict_size = dict_size + 1
      end
      w = c
    end
  end
  local code = dict[w]
  table.insert(res, string.char(math.floor(code / 256), code % 256))
  return table.concat(res)
end

local function decompress(data)
  if #data == 0 then return "" end
  local dict = {}
  for i = 0, 255 do dict[i] = string.char(i) end
  local dict_size, res = 256, {}
  local function get_code(idx)
    local b1, b2 = data:byte(idx, idx + 1)
    return b1 * 256 + b2
  end
  local prev_code = get_code(1)
  local w = dict[prev_code]
  table.insert(res, w)
  for i = 3, #data, 2 do
    local curr_code = get_code(i)
    local entry = ""
    if dict[curr_code] then
      entry = dict[curr_code]
    elseif curr_code == dict_size then
      entry = w .. w:sub(1, 1)
    end
    table.insert(res, entry)
    if dict_size < 65535 then
      dict[dict_size] = w .. entry:sub(1, 1)
      dict_size = dict_size + 1
    end
    w = entry
  end
  return table.concat(res)
end

local function get_file_stats(path)
  local attr = lfs.attributes(path)
  if not attr then return "0", "0", "644" end
  return tostring(attr.modification), tostring(attr.size), "644"
end

local function mkdir_p(path)
  local current = ""
  for part in path:gmatch("[^/]+") do
    current = current == "" and part or current .. "/" .. part
    lfs.mkdir(current)
  end
end

local function walk(dir, fn)
  for file in lfs.dir(dir) do
    if file ~= "." and file ~= ".." then
      local path = dir == "." and file or dir .. "/" .. file
      local mode = lfs.attributes(path, "mode")
      if mode == "directory" then
        walk(path, fn)
      elseif mode == "file" then
        fn(path)
      end
    end
  end
end

function hash_object(input)
  local content = ""
  if type(input) == "function" then
    while true do
      local c = input()
      if not c then break end
      content = content .. c
    end
  else content = input end
  local hash = sha1(content)
  local path = ".lvcs/objects/" .. hash
  local check = io.open(path, "rb")
  if check then check:close() return hash end
  local c_data = compress(content)
  local final_data = (#c_data < #content) and ("\1" .. c_data) or ("\0" .. content)
  local file = io.open(path, "wb")
  if file then
    file:write(final_data)
    file:close()
  end
  return hash
end

local function read_object(hash)
  local f = io.open(".lvcs/objects/" .. hash, "rb")
  if not f then return nil end
  local data = f:read("*all")
  f:close()
  local flag = data:sub(1, 1)
  local payload = data:sub(2)
  return (flag == "\1") and decompress(payload) or payload
end

local function read_index()
  local index = {}
  local f = io.open(".lvcs/index", "rb")
  if not f then return index end
  for line in f:lines() do
    local h, m, s, mo, n = line:match("(%w+) (%d+) (%d+) (%d+) (.+)")
    if h then index[n] = {hash = h, mtime = m, size = s, mode = mo} end
  end
  f:close()
  return index
end

local function write_index(index)
  local f = io.open(".lvcs/index", "wb")
  if f then
    for n, d in pairs(index) do
      f:write(string.format("%s %s %s %s %s\n", d.hash, d.mtime, d.size, d.mode, n))
    end
    f:close()
  end
end

local function get_ignore_list()
  local ignore = { [".lvcs"] = true }
  local f = io.open(".lvcsignore", "rb")
  if f then
    for line in f:lines() do
      local clean = line:gsub("%s+", "")
      if clean ~= "" and not clean:match("^#") then ignore[clean] = true end
    end
    f:close()
  end
  return ignore
end

local function should_ignore(path, ignore_list)
  local clean_path = path:gsub("^%./", "")
  if clean_path == ".lvcs" or clean_path:match("^%.lvcs/") then return true end
  for pattern in pairs(ignore_list) do
    if clean_path == pattern or clean_path:find("^" .. pattern .. "/") then return true end
  end
  return false
end

local function build_tree_recursive(files)
  local entries, subdirs = {}, {}
  for path, data in pairs(files) do
    local sep = path:find("/")
    if not sep then
      table.insert(entries, string.format("blob %s %s %s", data.hash, data.mode, path))
    else
      local dir, sub_path = path:sub(1, sep - 1), path:sub(sep + 1)
      subdirs[dir] = subdirs[dir] or {}
      subdirs[dir][sub_path] = data
    end
  end
  for dir, sub_files in pairs(subdirs) do
    local sub_hash = build_tree_recursive(sub_files)
    table.insert(entries, string.format("tree %s 755 %s", sub_hash, dir))
  end
  table.sort(entries)
  return hash_object(table.concat(entries, "\n") .. "\n")
end

local function parse_tree_recursive(t_hash, prefix, tree_out)
  prefix = prefix or ""
  local content = read_object(t_hash)
  if not content then return end
  for line in content:gmatch("[^\r\n]+") do
    local type, hash, mode, name = line:match("(%w+) (%w+) (%d+) (.+)")
    local full_path = prefix == "" and name or prefix .. "/" .. name
    if type == "blob" then tree_out[full_path] = {hash = hash, mode = mode}
    elseif type == "tree" then parse_tree_recursive(hash, full_path, tree_out) end
  end
end

local function get_tree(c_hash)
  local tree = {}
  if not c_hash or c_hash == "" or c_hash == "none" then return tree end
  local data = read_object(c_hash)
  if not data then return tree end
  local t_hash = data:match("^tree (%w+)")
  if t_hash then parse_tree_recursive(t_hash, "", tree) end
  return tree
end

local function get_head()
  local f = io.open(".lvcs/HEAD", "rb")
  if not f then return nil end
  local c = f:read("*a"):gsub("%s+", "")
  f:close()
  return c
end
local function get_current_branch()
  local h = get_head()
  return h and h:match("ref: refs/heads/(.+)") or "main"
end

function init()
  mkdir_p(".lvcs/objects")
  mkdir_p(".lvcs/refs/heads")
  mkdir_p(".lvcs/refs/tags")
  local f = io.open(".lvcsignore", "ab")
  if f then f:close() end
  local head = io.open(".lvcs/HEAD", "wb")
  if head then head:write("ref: refs/heads/main") head:close() end
  print("repo init success")
end

function add(path)
  if not path then return end
  local index, ignore = read_index(), get_ignore_list()
  local function add_file(p)
    p = p:gsub("^%./", "")
    if should_ignore(p, ignore) then return end
    local mtime, size, mode = get_file_stats(p)
    if index[p] and index[p].mtime == mtime and index[p].size == size then return end
    local f = io.open(p, "rb")
    if f then
      local hash = hash_object(function() return f:read(8192) end)
      f:close()
      index[p] = {hash = hash, mtime = mtime, size = size, mode = mode}
      print("staged " .. p)
    end
  end
  if path == "." then
    walk(".", add_file)
  else
    add_file(path)
  end
  write_index(index)
end

function del(path)
  local index = read_index()
  if index[path] then
    index[path] = nil
    os.remove(path)
    write_index(index)
    print("deleted: " .. path)
  end
end

function status()
  local index = read_index()
  local ignore = get_ignore_list()
  local head_ref = io.open(".lvcs/HEAD", "rb")
  local head_content = head_ref and head_ref:read("*a") or ""
  if head_ref then head_ref:close() end
  local head_commit =
    head_content:match("ref: refs/heads/(.+)")
    and io.open(".lvcs/refs/heads/" .. get_current_branch(), "rb"):read("*a")
    or head_content
  head_commit = (head_commit or ""):gsub("%s+", "")
  local head_tree = get_tree(head_commit)
  print("\nstaged:")
  for p, d in pairs(index) do
    local h = head_tree[p]
    if not h then
      print("  new: " .. p)
    elseif h.hash ~= d.hash then
      print("  modified: " .. p)
    end
  end
  print("\nnot staged:")
  walk(".", function(p)
    p = p:gsub("^%./", "")
    if should_ignore(p, ignore) then return end
    local m, s = get_file_stats(p)
    local idx = index[p]
    if idx and (idx.mtime ~= m or idx.size ~= s) then
      print("  modified: " .. p)
    end
  end)
  print("\nuntracked:")
  walk(".", function(p)
    p = p:gsub("^%./", "")
    if should_ignore(p, ignore) then return end
    if not index[p] then
      print("  " .. p)
    end
  end)
end

function commit(msg)
  if not msg or msg == "" then return end
  local branch = get_current_branch()
  if not branch then
    print("error: detached HEAD (checkout a branch first)")
    return
  end
  local index = read_index()
  if not next(index) then return end
  local tree_hash = build_tree_recursive(index)
  local head_path = ".lvcs/refs/heads/" .. branch
  local pf = io.open(head_path, "rb")
  local parent = pf and pf:read("*a"):gsub("%s+", "") or "none"
  if pf then pf:close() end
  local c_data = string.format("tree %s\nparent %s\nmessage %s\n",tree_hash,parent,msg)
  local c_hash = hash_object(c_data)
  local bf = io.open(head_path, "wb")
  if bf then
    bf:write(c_hash)
    bf:close()
  end
  print("committed: " .. c_hash:sub(1,7))
end

function branch(name)
  if not name then
    local curr = get_current_branch()
    for b in lfs.dir(".lvcs/refs/heads") do
      if b ~= "." and b ~= ".." then
        local prefix = (b == curr) and "* " or "  "
        print(prefix .. b)
      end
    end
    return
  end
  local curr_branch = get_current_branch()
  local f = io.open(".lvcs/refs/heads/" .. curr_branch, "rb")
  local latest = f and f:read("*a") or ""
  if f then f:close() end
  local nf = io.open(".lvcs/refs/heads/" .. name, "wb")
  if nf then nf:write(latest) nf:close() end
  print("create branch: " .. name)
end

local function resolve_hash(short)
  if #short < 4 or #short >= 40 then return short end
  for file in lfs.dir(".lvcs/objects") do
    if file:sub(1, #short) == short then return file end
  end
  return short
end

function checkout(target)
  local branch_path = ".lvcs/refs/heads/" .. target
  local f_branch = io.open(branch_path, "rb")
  local is_branch = f_branch ~= nil
  local c_hash = is_branch and f_branch:read("*a"):gsub("%s+", "") or resolve_hash(target)
  if f_branch then f_branch:close() end
  local test_f = io.open(".lvcs/objects/" .. c_hash, "rb")
  if not test_f then
    print("error: target not found")
    return
  end
  test_f:close()
  if is_branch then
    local h = io.open(".lvcs/HEAD", "wb")
    if h then h:write("ref: refs/heads/" .. target) h:close() end
  else
    local h = io.open(".lvcs/HEAD", "wb")
    if h then h:write(c_hash) h:close() end
  end
  local old_index, tree, new_index = read_index(), get_tree(c_hash), {}
  for n in pairs(old_index) do if not tree[n] then os.remove(n) end end
  for n, d in pairs(tree) do
    local dir = n:match("(.+)/")
    if dir then mkdir_p(dir) end
    local content, out = read_object(d.hash), io.open(n, "wb")
    if content and out then
      out:write(content)
      out:close()
    end
    local m, s, mo = get_file_stats(n)
    new_index[n] = {hash = d.hash, mtime = m, size = s, mode = mo}
  end
  write_index(new_index)
  print(is_branch
  and ("switched to branch " .. target)
  or ("HEAD detached at " .. c_hash:sub(1,7)))

end

local function get_history(hash)
  local hist, curr = {}, hash
  while curr and curr ~= "none" and curr ~= "" do
    hist[curr] = true
    local data = read_object(curr)
    if not data then break end
    curr = data:match("parent (%w+)")
  end
  return hist
end

function merge(other)
  local curr_b = get_current_branch()
  local f1, f2 = io.open(".lvcs/refs/heads/" .. curr_b, "rb"), io.open(".lvcs/refs/heads/" .. other, "rb")
  if not f1 or not f2 then print("branch not found") return end
  local h1, h2 = f1:read("*a"):gsub("%s+", ""), f2:read("*a"):gsub("%s+", "")
  f1:close() f2:close()
  local hist1, ancestor, c = get_history(h1), nil, h2
  while c and c ~= "none" do
    if hist1[c] then ancestor = c break end
    local data = read_object(c)
    c = data and data:match("parent (%w+)") or nil
  end
  local t_base, t1, t2 = get_tree(ancestor), get_tree(h1), get_tree(h2)
  local index, conflict, all = read_index(), false, {}
  for n in pairs(t1) do all[n] = true end
  for n in pairs(t2) do all[n] = true end
  for n in pairs(all) do
    local b, cur, oth = t_base[n], t1[n], t2[n]
    if (not cur and oth) or (cur and oth and cur.hash ~= oth.hash) or (cur and not oth) then
      if b and cur and b.hash == cur.hash then
        if not oth then
          os.remove(n)
          index[n] = nil
        else
          local dir = n:match("(.+)/")
          if dir then mkdir_p(dir) end
          local content, out = read_object(oth.hash), io.open(n, "wb")
          if content and out then
            out:write(content)
            out:close()
          end
          local m, s, mo = get_file_stats(n)
          index[n] = {hash = oth.hash, mtime = m, size = s, mode = mo}
          print("  updated: " .. n)
        end
      elseif (not b and cur and oth) or (b and oth and b.hash ~= oth.hash) then
        conflict = true
        print("  conflict: " .. n)
        local c1 = cur and read_object(cur.hash) or ""
        local c2 = oth and read_object(oth.hash) or ""
        local out = io.open(n, "wb")
        if out then
          out:write(
            "<<<<<<< HEAD\n" ..
            c1 ..
            "=======\n" ..
            c2 ..
            ">>>>>>> " .. other .. "\n"
          )
          out:close()
        end
        index[n] = nil
      end
    end
  end
  if not conflict then write_index(index) commit("merged " .. other) else print("fix conflicts and commit manually") end
end

function log()
  local b = get_current_branch()
  local f = io.open(".lvcs/refs/heads/" .. b, "rb")
  local curr = f and f:read("*a"):gsub("%s+", "") or ""
  if f then f:close() end
  while curr and curr ~= "none" and curr ~= "" do
    local data = read_object(curr)
    if not data then break end
    print(string.format("[%s] %s", curr:sub(1,7), data:match("message (.*)") or ""))
    curr = data:match("parent (%w+)")
  end
end

function undo(path)
  if not path then return end
  local b = get_current_branch()
  local hf = io.open(".lvcs/refs/heads/" .. b, "rb")
  local hh = hf and hf:read("*a"):gsub("%s+", "") or ""
  if hf then hf:close() end
  local tree, idx = get_tree(hh), read_index()
  local function restore(p, d)
    local content, out = read_object(d.hash), io.open(p, "wb")
    if content and out then
      out:write(content)
      out:close()
    end
    local m, s, mo = get_file_stats(p)
    idx[p] = {hash = d.hash, mtime = m, size = s, mode = mo}
    print("restored " .. p)
  end
  if path == "." then
    walk(".", function(n)
      n = n:gsub("^%./", "")
      if not should_ignore(n, get_ignore_list()) and not tree[n] then
        os.remove(n)
        idx[n] = nil
        print("removed untracked " .. n)
      end
    end)
    for p, d in pairs(tree) do restore(p, d) end
  elseif tree[path] then restore(path, tree[path])
  else print("not found in commit") end
  write_index(idx)
end

function tag(name)
  if not name then
    for t in lfs.dir(".lvcs/refs/tags") do
      if t ~= "." and t ~= ".." then
        local f = io.open(".lvcs/refs/tags/"..t,'rb')
        print(t..": "..f:read():sub(1,7)) 
        f:close()
      end
    end
    return
  end
  local branch = get_current_branch()
  local f = io.open(".lvcs/refs/heads/" .. branch, "rb")
  local hash = f and f:read("*a"):gsub("%s+", "") or ""
  if f then f:close() end
  local tf = io.open(".lvcs/refs/tags/" .. name, "wb")
  if tf then
    tf:write(hash)
    tf:close()
    print("tagged " .. hash:sub(1,7) .. " as " .. name)
  end
end

local cmd = arg[1]
if cmd == "init" then init()
elseif cmd == "add" then add(arg[2])
elseif cmd == "del" then del(arg[2])
elseif cmd == "commit" then commit(arg[2])
elseif cmd == "status" then status()
elseif cmd == "log" then log()
elseif cmd == "checkout" then checkout(arg[2])
elseif cmd == "branch" then branch(arg[2])
elseif cmd == "merge" then merge(arg[2])
elseif cmd == "undo" then undo(arg[2])
elseif cmd == "tag" then tag(arg[2])
else print("Usage: lua lvcs.lua [init|add|del|commit|status|log|checkout|branch|merge|undo]") end
