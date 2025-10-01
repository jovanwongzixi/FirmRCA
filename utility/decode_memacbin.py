import struct, subprocess, tempfile, sys

# FNAME = '/home/jovan/FirmRCA/testsuites/p2im-11/memac.bin'
# FNAME = '/home/jovan/FirmRCA/tmp/memac.bin'
# FNAME = '/home/jovan/FirmRCA_multi_arch/testsuites/u-boot/memac.bin'
FNAME = '/home/jovan/imba/projects/llama.cpp/memac.bin'
# SCHEMA = '/home/jovan/FirmRCA/fuzzware-emulator/harness/fuzzware_harness/tracing/bintrace.capnp'
SCHEMA = '/home/jovan/FirmRCA_multi_arch/test_c_capnproto/bintrace.capnp'
TYPE = 'TraceEvent'

with open(FNAME, 'rb') as f:
    idx = 0
    while True:
        hdr0 = f.read(8)                 # two 32-bit words minimum
        if not hdr0 or len(hdr0) < 8:
            break
        segcount_minus1, first_len = struct.unpack('<II', hdr0)
        segcount = segcount_minus1 + 1
        seglens = [first_len]
        if segcount > 1:
            remaining = f.read(4*(segcount-1))
            if len(remaining) < 4*(segcount-1):
                print("Unexpected EOF reading segment lengths", file=sys.stderr)
                break
            seglens += list(struct.unpack('<'+'I'*(segcount-1), remaining))
        # header padded to multiple of 8 bytes:
        header_bytes = struct.pack('<I', segcount_minus1) + b''.join(struct.pack('<I', L) for L in seglens)
        if (len(header_bytes) % 8) != 0:
            header_bytes += b'\x00\x00\x00\x00'
        payload_words = sum(seglens)
        payload_bytes = payload_words * 8
        payload = f.read(payload_bytes)
        if len(payload) < payload_bytes:
            print("Unexpected EOF reading payload", file=sys.stderr)
            break
        # write full message (header + payload) to temp file and decode
        with tempfile.NamedTemporaryFile(delete=False) as t:
            t.write(header_bytes)
            t.write(payload)
            t.flush()
            # print("Message", idx)
            subprocess.run(['capnp', 'decode', SCHEMA, TYPE], stdin=open(t.name, 'rb'))
        idx += 1