#!/usr/bin/env python3

import frida
import sys

def int_to_scan_string(num):
    num_int = int(num)
    return '%02x %02x %02x %02x' % (
        num_int & 0xff, 
        (num_int >> 8) & 0xff,
        (num_int >> 16) & 0xff,
        (num_int >> 24) & 0xff,
    )

def str_to_scan_string(in_str):
    return ' '.join(hex(ord(c))[2:] for c in in_str)

if len(sys.argv) != 4:
    print("Usage: set_monies.py OLD_MONIES OLD_RANK NAME")
    sys.exit(1)

print(sys.argv[1])
monies_str = int_to_scan_string(sys.argv[1])
print(monies_str)
rank_str = int_to_scan_string(sys.argv[2])
print(rank_str)
name_str = str_to_scan_string(sys.argv[3])

session = frida.attach("snowrunner.exe")
script = session.create_script("""
    var ranges = Process.enumerateRanges('rw-');

    function on_match(address, size) {
        console.log('[+] Pattern found at: ' + address.toString());
        //Memory.writeInt(address, 111235);
    }

    console.log('START');

   for (var i in ranges) {
        var results = Memory.scanSync(ranges[i].base, ranges[i].size, '%s');
        for (var j in results) {
            // Found old money value in current range, keep looking for 
            // other variables.
            console.log('range=' + JSON.stringify(ranges[i]));
            console.log('address=' + results[j].address);

            var new_search = {
                'base': '0x' + (parseInt(results[j].address, 16) - 64).toString(16),
                'size':  128
            }
            console.log('new_search=' + JSON.stringify(new_search));

            var profile_name = Memory.scanSync(ptr(new_search.base), new_search.size, '%s');
            for (var k in profile_name) {
                console.log('name=' + profile_name[k].address);
            }
            var rank = Memory.scanSync(ptr(new_search.base), new_search.size, '%s');
            for (var k in rank) {
                console.log('rank=' + rank[k].address);
            }
            console.log('NEXT');
        }
    }

    console.log('FINISHED');

""" % (monies_str, name_str, rank_str))
script.load()
sys.stdin.read()



