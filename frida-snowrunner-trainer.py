#!/usr/bin/env python3

import frida
import sys

# From: https://www.maprunner.info/resources/rank-xp
xp_table = [
    (0, 0),
    (700, 0),
    (1000, 700),
    (1200, 1700),
    (1200, 2900),
    (1300, 4100),
    (1500, 5400),
    (1600, 6900),
    (1600, 8500),
    (1700, 10100),
    (1900, 11800),
    (2000, 13700),
    (2100, 15700),
    (2300, 17800),
    (2400, 20100),
    (2500, 22500),
    (2500, 25000),
    (2600, 27500),
    (2600, 30100),
    (2800, 32700),
    (2800, 35500),
    (3000, 38300),
    (3000, 41300),
    (3200, 44300),
    (3200, 47500),
    (3400, 50700),
    (3400, 54100),
    (3600, 57500),
    (3800, 61100),
    (4100, 64900),
    (0   , 69000)
]


def int_to_scan_string(num):
    '''Converts an Integer to the search string required by scanSync.'''

    return '%02x %02x %02x %02x' % (
        num & 0xff, 
        (num >> 8) & 0xff,
        (num >> 16) & 0xff,
        (num >> 24) & 0xff,
    )

def str_to_scan_string(in_str):
    '''Converts a String to the search string required by scanSync.'''

    return ' '.join(hex(ord(c))[2:] for c in in_str)

def get_total_xp(rank, xp):
    '''Calculates total XP from rank and relative XP.'''

    return xp_table[rank][1] + xp

if len(sys.argv) != 7:
    print("Usage: frida-snowrunner-trainer.py CURRENT_MONEY CURRENT_RANK CURRENT_XP PROFILE_NAME NEW_MONEY NEW_RANK")
    sys.exit(1)

# Some of the parameter we can use as they are
cur_rank = int(sys.argv[2])
cur_xp = int(sys.argv[3])
new_money = int(sys.argv[5])
new_rank = int(sys.argv[6])
# Some need to get converted to hex strings for Frida
cur_money_str = int_to_scan_string(int(sys.argv[1]))
cur_rank_str = int_to_scan_string(cur_rank)
name_str = str_to_scan_string(sys.argv[4])
# Since we only get a number of XP points relativ to
# the current rank, we have to calculate the absolute
# value we need to look for in memory
total_cur_xp = get_total_xp(cur_rank, cur_xp)
total_cur_xp_str = int_to_scan_string(total_cur_xp)
new_xp = get_total_xp(new_rank, cur_xp)

session = frida.attach("snowrunner.exe")
script = session.create_script("""
    var candidates = [];
    var new_money = %d;
    var new_rank = %d;
    var new_xp = %d;

    // Get a list of all memory ranges mapped by the process.
    var ranges = Process.enumerateRanges('rw-');

    for (var i in ranges) {
        // We can skip very large and very small ranges.
        // Depending on the patch level the profile data are
        // located in ranges of 128 to 512kb
        if (ranges[i].size < 128*1024 || ranges[i].size > 512*1024) {
            continue;
        }

        // Scan the range for the current profile account balance
        var results = Memory.scanSync(ranges[i].base, ranges[i].size, '%s');

        for (var j in results) {
            // If the currenct account balance is found i a memory range
            // keep scanning the range for the other data we are
            // interested in

            console.log('range=' + JSON.stringify(ranges[i]));
            console.log('money=' + results[j].address);

            var addr_money = results[j].address;
            var addr_rank = '';
            var addr_xp = '';

            //var new_search = {
            //    'base': '0x' + (parseInt(results[j].address, 16) - 384).toString(16),
            //    'size':  768
            //}
            //console.log('new_search=' + JSON.stringify(new_search));

            // We don't need to scan the whole range but just a couple hundred
            // bytes before and after the location of the account balance
            var new_base = '0x' + (parseInt(results[j].address, 16) - 384).toString(16);
            var new_size = 768

            // The profile name is currently not used since it seems to be stored
            // in different formats in memory depending on various factors, e.g.
            // if includes non alphanumeric characters.
            // Since the target memory area can be identified reliably without
            // the profile name as a reference point we can skip it to reduce
            // complexity.
            //var profile_name = Memory.scanSync(ptr(new_search.base), new_search.size, '%s');
            //for (var k in profile_name) {
            //    console.log('name=' + profile_name[k].address);
            //    addr_name = profile_name[k].address;
            //}

            // The base address needs to be a pointer type for scanSync(), so
            // we need to convert it from string to pointer with ptr().
            var rank = Memory.scanSync(ptr(new_base), new_size, '%s');
            for (var k in rank) {
                console.log('rank=' + rank[k].address);
                addr_rank = rank[k].address;
            }
            var xp = Memory.scanSync(ptr(new_base), new_size, '%s');
            for (var k in xp) {
                console.log('xp=' + xp[k].address);
                addr_xp = xp[k].address;
            }

            // If we found all the values we were looking for, save the locations
            // in an array of possible memory locations to update.
            if (addr_money && addr_rank && addr_xp) {
                candidates.push({'rank': addr_rank, 'money': addr_money, 'xp': addr_xp});
            }
        }
    }

    if (candidates.length) {
        console.log('Found candidates: ' + JSON.stringify(candidates));
    } else {
        console.log('Target data not found.');
    }

    if (candidates.length == 1) {
        // We found our target values in exactly one location, so
        // it should be safe to update them there.

        console.log('Updating data!');
        Memory.writeInt(candidates[0].money, new_money);
        Memory.writeInt(candidates[0].rank, new_rank);
        Memory.writeInt(candidates[0].xp, new_xp);
    } else if (candidates.length > 1) {
        // In this case we found multiple possible target locations.
        // It is probably still safe to update them as the game might
        // simply store multiple copies of the profile data, but
        // this could also indicate a false positive, so proceed with
        // caution!

        console.log('Ambiguous result.');
        for (var c in candidates) {
            console.log('Updating ' + c);
            Memory.writeInt(candidates[c].money, new_money);
            Memory.writeInt(candidates[c].rank, new_rank);
            Memory.writeInt(candidates[c].xp, new_xp);
        }
    }

""" % (new_money, new_rank, new_xp, cur_money_str, name_str, cur_rank_str, total_cur_xp_str))
script.load()

input('Press <Enter> to quit.')
