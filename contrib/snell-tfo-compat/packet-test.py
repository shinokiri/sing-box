"""Run compiled TC programs against generated packets in the actual kernel.

The tests do not transmit these packets. Input is the two program IDs returned
by tc. No dependency on bpftool, a compiler or a Python package on the relay.
"""
import ctypes as C
import ipaddress
import json
import os
import struct
import sys
import time

ids = json.load(sys.stdin)
lib = C.CDLL('libbpf.so.1', use_errno=True)
libc = C.CDLL(None, use_errno=True)
fds = {name: lib.bpf_prog_get_fd_by_id(ident) for name, ident in ids.items()}
assert all(fd >= 0 for fd in fds.values())
mapfd = lib.bpf_obj_get(sys.argv[1].encode())
assert mapfd >= 0

class Test(C.Structure):
    _fields_ = [(x, C.c_uint32) for x in ['fd','retval','in_size','out_size']] + [
        ('data_in', C.c_uint64), ('data_out', C.c_uint64)] + [
        (x, C.c_uint32) for x in ['repeat','duration','ctx_in_size','ctx_out_size']] + [
        ('ctx_in',C.c_uint64), ('ctx_out',C.c_uint64),
        ('flags',C.c_uint32), ('cpu',C.c_uint32), ('batch_size',C.c_uint32)]

def execute(which, packet, repeat=1):
    src=C.create_string_buffer(packet); dst=C.create_string_buffer(8192)
    a=Test(fd=fds[which],in_size=len(packet),out_size=len(dst),
           data_in=C.addressof(src),data_out=C.addressof(dst),repeat=repeat)
    # Relay is Linux x86_64; __NR_bpf is 321, BPF_PROG_TEST_RUN is 10.
    if libc.syscall(321,10,C.byref(a),C.sizeof(a)):
        raise OSError(C.get_errno(), 'BPF_PROG_TEST_RUN')
    assert a.retval == 0xffffffff, (which,a.retval)
    return dst.raw[:a.out_size],a.duration

def checksum(data):
    if len(data)%2:data+=b'\0'
    s=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
    while s>>16:s=(s&65535)+(s>>16)
    return (~s)&65535

def make(family, outgoing, seq, ack=0, flags=2, payload=b'', port=23791, sport=41000, options=0):
    client=ipaddress.ip_address('192.0.2.11' if family==4 else '2001:db8:1::11').packed
    server=ipaddress.ip_address('198.51.100.22' if family==4 else '2001:db8:2::22').packed
    src,dst=(server,client) if outgoing else (client,server)
    sp,dp=(port,sport) if outgoing else (sport,port)
    tcp=bytearray(struct.pack('!HHIIBBHHH',sp,dp,seq&0xffffffff,ack&0xffffffff,(5+options//4)<<4,flags,65535,0,0)+b'\1'*options+payload)
    pseudo=src+dst+(struct.pack('!BBH',0,6,len(tcp)) if family==4 else struct.pack('!I3xB',len(tcp),6))
    struct.pack_into('!H',tcp,16,checksum(pseudo+tcp))
    if family==4:
        ip=bytearray(struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(tcp),123,0x4000,64,6,0,src,dst))
        struct.pack_into('!H',ip,10,checksum(ip))
    else:ip=struct.pack('!IHBB16s16s',6<<28,len(tcp),6,64,src,dst)
    return b'\0'*12+struct.pack('!H',0x0800 if family==4 else 0x86dd)+ip+tcp

def payload(mark=True, size=496):
    p=bytearray(b'\xa5'*size)
    p[:11]=b'\x16\x03\x01'+struct.pack('!H',size-5)+b'\x01\0'+struct.pack('!H',size-9)+b'\x03\x03'
    if mark:p[11:19]=b'CTFO\x01\0\0\0'
    return bytes(p)

checks=[]
abi_rejected_short_packets=[]
def check(name, actual, expected):
    assert actual==expected,name
    checks.append(name)

for family in [4,6]:
    size=496 if family==4 else 1180
    prefix=f'ipv{family}:'
    for i,isn in enumerate([1000,0xfffffff0]):
        sport=41000+i
        syn=make(family,False,isn,payload=payload(size=size),sport=sport,options=40)
        check(prefix+'incoming_payload_unchanged',execute('ingress',syn)[0],syn)
        synack=make(family,True,9000,ack=isn+1+size,flags=18,sport=sport,options=40)
        expected=make(family,True,9000,ack=isn+1,flags=18,sport=sport,options=40)
        check(prefix+'synack_ack_and_checksum',execute('egress',synack)[0],expected)
        check(prefix+'retransmitted_synack',execute('egress',synack)[0],expected)
        empty_syn=make(family,False,isn,sport=sport)
        execute('ingress',empty_syn)
        check(prefix+'fallback_syn_keeps_same_handshake',execute('egress',synack)[0],expected)
        early=make(family,True,9001,ack=isn+1+size,flags=24,payload=b'early reply',sport=sport)
        check(prefix+'early_reply_byte_exact',execute('egress',early)[0],early)
        client_data=make(family,False,isn+1,payload=payload(size=size),ack=9001,flags=24,sport=sport)
        check(prefix+'ordinary_retransmit_byte_exact',execute('ingress',client_data)[0],client_data)
        for ack in [isn+1,isn+size,isn+size+2]:
            other=make(family,True,9000,ack=ack,flags=18,sport=sport)
            check(prefix+'unmatched_ack_unchanged',execute('egress',other)[0],other)
        # A new connection with the same tuple must discard old pending state.
        execute('ingress',make(family,False,isn+77,sport=sport))
        check(prefix+'new_isn_clears_stale_tuple',execute('egress',synack)[0],synack)
    for i,kind in enumerate(['unmarked','cold_cookie','wrong_port','unknown_version']):
        sport=42000+i; port=23790 if kind=='wrong_port' else 23791
        data=payload(mark=kind!='unmarked',size=size)
        if kind=='cold_cookie':data=b''
        if kind=='unknown_version':data=data[:15]+b'\x02'+data[16:]
        syn=make(family,False,2000,payload=data,port=port,sport=sport)
        execute('ingress',syn)
        reply=make(family,True,9000,ack=2001+len(data),flags=18,port=port,sport=sport)
        check(prefix+kind,execute('egress',reply)[0],reply)
    syn=make(family,False,3000,payload=payload(size=size),sport=43000)
    execute('ingress',syn)
    client=ipaddress.ip_address('192.0.2.11' if family==4 else '2001:db8:1::11').packed.ljust(16,b'\0')
    server=ipaddress.ip_address('198.51.100.22' if family==4 else '2001:db8:2::22').packed.ljust(16,b'\0')
    key=C.create_string_buffer(client+server+struct.pack('!HH',43000,23791)+struct.pack('I',family))
    value=C.create_string_buffer(struct.pack('QII',time.monotonic_ns()-200_000_000_000,3000,size))
    assert lib.bpf_map_update_elem(mapfd,key,value,C.c_uint64(0))==0
    reply=make(family,True,9000,ack=3001+size,flags=18,sport=43000)
    check(prefix+'expired_entry',execute('egress',reply)[0],reply)
    # Short packets never mutate state or contents. Ethernet itself is required
    # by the test-run ABI, so lengths below 14 are not valid test inputs.
    for n in range(14,14+(20 if family==4 else 40)+20):
        short=syn[:n]
        try:
            result=execute('ingress',short)[0]
        except OSError as e:
            if e.errno!=22:raise
            abi_rejected_short_packets.append({'family':family,'length':n})
            continue
        check(prefix+'truncated_'+str(n),result,short)

bench=[]
for family in [4,6]:
    data=make(family,True,8000,ack=4000,flags=24,payload=b'x'*1300)
    for direction in ['ingress','egress']:
        times=[]
        for _ in range(5):
            out,duration=execute(direction,data,50000)
            assert out==data
            times.append(duration)
        bench.append({'family':family,'direction':direction,'ordinary_packet_ns':times})
# Force LRU eviction without transmitting traffic or growing kernel state
# beyond the configured bound. A newly inserted handshake must still adapt.
for i in range(18000):
    execute('ingress',make(4,False,7000+i,payload=payload(),sport=10000+i))
reply=make(4,True,9000,ack=7000+17999+1+496,flags=18,sport=27999)
expected=make(4,True,9000,ack=7000+17999+1,flags=18,sport=27999)
check('lru_pressure_preserves_new_handshake',execute('egress',reply)[0],expected)
lib.bpf_map_get_next_key.argtypes=[C.c_int,C.c_void_p,C.c_void_p]
key=None; entries=0
while True:
    next_key=C.create_string_buffer(40)
    if lib.bpf_map_get_next_key(mapfd,key,next_key):break
    entries+=1;key=next_key
    assert entries<=16384,'map grew beyond its fixed bound'
check('lru_pressure_is_bounded',0<entries<=16384,True)
for fd in list(fds.values())+[mapfd]:os.close(fd)
print(json.dumps({'kind':'kernel_selftest','checks':len(checks),'passed':True,
                  'checks_list':checks,'abi_rejected_short_packets':abi_rejected_short_packets,
                  'kernel_program_microbench':bench}))
