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

if len(sys.argv) != 6:
    print("Usage: set_monies.py OLD_MONIES OLD_RANK NAME NEW_MONIES NEW_RANK")
    sys.exit(1)

monies_str = int_to_scan_string(sys.argv[1])
rank_str = int_to_scan_string(sys.argv[2])
name_str = str_to_scan_string(sys.argv[3])
new_monies = int(sys.argv[4])
new_rank = int(sys.argv[5])

session = frida.attach("snowrunner.exe")
script = session.create_script("""
    var ranges = Process.enumerateRanges('rw-');
    var candidates = [];

    for (var i in ranges) {
        var results = Memory.scanSync(ranges[i].base, ranges[i].size, '%s');
        for (var j in results) {
            // Found old money value in current range, keep looking for 
            // other variables.
            console.log('range=' + JSON.stringify(ranges[i]));
            console.log('money=' + results[j].address);
            var addr_money = results[j].address;
            var addr_name = '';
            var addr_rank = '';


            var new_search = {
                'base': '0x' + (parseInt(results[j].address, 16) - 64).toString(16),
                'size':  128
            }
            console.log('new_search=' + JSON.stringify(new_search));

            var profile_name = Memory.scanSync(ptr(new_search.base), new_search.size, '%s');
            for (var k in profile_name) {
                console.log('name=' + profile_name[k].address);
                addr_name = profile_name[k].address;
            }
            var rank = Memory.scanSync(ptr(new_search.base), new_search.size, '%s');
            for (var k in rank) {
                console.log('rank=' + rank[k].address);
                addr_rank = rank[k].address;
            }
            if (addr_name && addr_money && addr_rank) {
                candidates.push({'name': addr_name, 'rank': addr_rank, 'money': addr_money});
            }
        }
    }

    if (candidates.length) {
        console.log('Found candidates: ' + JSON.stringify(candidates));
    } else {
        console.log('Target data not found.');
    }

    if (candidates.length == 1) {
        console.log('Updating data!');
        Memory.writeInt(candidates[0].money, %d);
        Memory.writeInt(candidates[0].rank, %d);
    } else if (candidates.length > 1) {
        console.log('Ambiguous result. Not updating!');
    }

""" % (monies_str, name_str, rank_str, new_monies, new_rank))
script.load()

input('Press <Enter> to quit.')
