import angr

finds = []
avoids = []
index = 0

data = open('./RedVelvet', 'rb').read()
while True:
    # find the 'mov flag, 0'
    # add them to the avoid list
    res = data.find('\xbf\x01\x00\x00\x00', index)
    if res == -1:
        break
    avoids.append(0x400000 + res)
    index = res + 1

index = 0
while True:
    # find the 'mov edi, offset s'
    # add them to the find list
    res = data.find('\xbf\xc4\x16\x40\x00', index)
    if res == -1:
        break
    finds.append(0x400000 + res)
    index = res + 1

print finds, avoids

p = angr.Project('./RedVelvet', load_options = {'auto_load_libs': False})
state = p.factory.entry_state()
# we do find in multiple stages to monitor angr's progress
for find in finds:
    print hex(find)
    simgr = p.factory.simgr(state)
    simgr.explore(find = find, avoid = avoids)
    state = simgr.found[0]
    print state.posix.dumps(0)

