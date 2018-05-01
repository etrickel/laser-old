import json
from base64 import b64decode
import random
from binascii import hexlify
import os
from os.path import exists
from subprocess import Popen, PIPE
# from pwn import *
from termcolor import colored, cprint
import IPython
from operator import itemgetter
import ipdb

with open("results.json", "r") as jf:
    j = json.load(jf)

inps = {}

def repeated_input(jdata):
    for run in jdata:
        for inp in run:
            if inp["hash_bb"] in inps:
                inps[inp["hash_bb"]]["input"].add(inp["input"])
                inps[inp["hash_bb"]]["count"] += 1
            else:
                inps[inp["hash_bb"]] = {"input": set([inp["input"]]), "count": 1}

    for succ_key, v in inps.items():
        if v["count"] > 2:
            break_index = 2
            decoded_inp = [str(b64decode(x))[:10] for x in list(v["input"])[:break_index]]
            inp_out = " ".join(decoded_inp)

            if len(v["input"]) == 1:
                cprint("Total:{:03d} Unique:{:03d} \tInput: |>{}<|".format(v["count"], len(v["input"]), repr(inp_out)),
                       "green")
            else:
                print("Total:{:03d} Unique:{:03d} \tInput: |>{}<|".format(v["count"], len(v["input"]), repr(inp_out)))

def find_links(jdata):
    all_preds = {}

    #find all direct predecessors and track earliest pos in input it was found
    for run in jdata:
        for inpindex in range(1, len(run)):
            curr = run[inpindex]["hash_bb"]
            pred = run[inpindex - 1]["hash_bb"]
            if curr not in all_preds:
                all_preds[curr] = {"preds": set(), "earliest_pos": inpindex}
            all_preds[curr]["preds"].add(pred)
            if inpindex < all_preds[curr]["earliest_pos"]:
                all_preds[curr]["earliest_pos"] = inpindex

    # reduce down to only those who have a single predecessor
    # for a given HEAD it is ALWAYS preceeded by MinionX
    single_preds = {}
    for k, v in all_preds.items():
        if len(v["preds"]) == 1:
            single_preds[k] = {"preds": list(v["preds"])[0], "earliest_pos": v["earliest_pos"]}

    # Look for HEADS that have more than one Minion following them
    # MinionX is followed by MinionY, which might be followed by MinionZ, etc...
    full_preds = {}
    for k, d in single_preds.items():
        full_preds[k] = {"preds": [d["preds"]], "earliest_pos": d["earliest_pos"]}
        test = d["preds"]
        while test in single_preds:
            test = single_preds[test]["preds"]
            full_preds[k]["preds"].append(test)


    # delete shorter trains, only the longest survives
    for k, d in full_preds.items():
        if d["preds"][0] in full_preds:
            cprint("DELETING {} {} b/c it's shorter than {} with {}"
                   .format(d["preds"][0], full_preds[d["preds"][0]], k, d["preds"]), "red")
            del full_preds[d["preds"][0]]

    # delete trains that have the HEAD appear in the first node of a run
    for k, d in full_preds.items():
        for run in jdata:
            if len(run) > 0:
                if run[0]["hash_bb"] == k:
                    cprint("\nDELETING {} {} b/c the head is at the start of a run, so cannot be a train\n"
                           .format(k, d))
                    del full_preds[k]
                    break

    # create static tuple train
    for k, d in full_preds.items():
        train = [ x for x in d["preds"] ]
        train = train[::-1] #reverse
        train.append(k)
        #train shold be in MinionZ -> MinionY -> MinionX -> HEAD ordering
        d["train"] = tuple(train)

    # TEST: does a HEAD exist with different MinionX
    for k, d in full_preds.items():
        for run in jdata:
            run_hashes = [x["hash_bb"] for x in run]
            if k in run_hashes:
                head_index = run_hashes.index(k)
                for train_index in range(0, len(d["preds"])):
                    if head_index > 0 and d["preds"][train_index] != run_hashes[head_index- train_index - 1]:
                        print "\n***We have a problem***\n"
                        print("{} {}\n{} {}".format(train_index, d["preds"][train_index], head_index- train_index - 1, run_hashes[head_index- train_index - 1]))
                        ipdb.set_trace()

    cnt = 0
    for k, d in sorted(full_preds.items(), key=lambda x: x[1]["earliest_pos"]):
        cnt += 1
        if d["earliest_pos"] < 20:
            print("{}) {} {} ".format(cnt, d["earliest_pos"], d["train"]))
        else:
            cprint("{}) {} {} ".format(cnt, d["earliest_pos"], d["train"]), "green")

    return full_preds

"""
for the execution given, group together the trains as a single entity, this will allow for intersecting on 
entire train 
"""
def group_up(exec_path, full_preds):
    final_path = []
    store_up = []
    occurences = []
    for i in range(0, len(exec_path)):
        curr_node = exec_path[i]
        # do we have the head of a train?
        if curr_node in full_preds:
            # if next is an instruction add to store and go to it, precendence to latest head and longest train
            if (i+1) < len(exec_path) and exec_path[i+1] in full_preds:
                store_up.append(curr_node)
                break

            preds = full_preds[curr_node]["preds"]
            prev_index = 1
            group = [curr_node]
            for pd in preds:
                if pd != exec_path[i - prev_index]:
                    raise Exception("error expected prev was not there")
                else:
                    group.append(pd)
                    try:
                        del store_up[-1]
                    except IndexError as ie:
                        ipdb.set_trace()
                        #import IPython
                        #IPython.embed()
                prev_index += 1

            #final_path.extend(store_up)
            for x in store_up:
                prior_occs = occurences.count(x)
                final_path.append((x, prior_occs))
                occurences.append(x)

            # reversing because start with successor and move backward and append to list
            tup_group = tuple(group[::-1])
            # TEST: that ordering is correct
            if full_preds[curr_node]["train"] != tup_group:
                print("{} {} ".format(curr_node, full_preds[curr_node]["train"], tup_group))
                ipdb.set_trace()

            prior_occs = final_path.count(tup_group)
            final_path.append((tup_group, prior_occs))
            occurences.append(tup_group)
            store_up = []
        else:
            store_up.append(curr_node)

    if len(store_up) > 0:
        for x in store_up:
            prior_occs = occurences.count(x)
            final_path.append((x, prior_occs))
            occurences.append(x)

    return set(final_path)

"""
looking across all runs, find trains that are always preceeded by what nodes
"""
def find_mandatory_pred(full_preds, jdata):
    to_delete = []
    for fp_curr, seq_data in full_preds.items():

        preds_interx = None
        inter_sects = 0
        for run in jdata:

            set_o_preds = set()

            for i in reversed(range(1, len(run))):
                if run[i]["hash_bb"] == fp_curr:
                    temp = run[:i - len(seq_data["preds"])]
                    set_o_preds = group_up([the_preds["hash_bb"] for the_preds in temp], full_preds)

            if len(set_o_preds) > 0:
                if preds_interx is None:
                    inter_sects = 1
                    preds_interx = set_o_preds
                else:
                    inter_sects += 1
                    preds_interx = set.intersection(preds_interx, set_o_preds)

        if preds_interx is None:
            to_delete.append(fp_curr)
            continue

        seq_data["inter_sects"] = inter_sects
        # seq_data["common_inp"]

        final_common_preds = [pd[0] for pd in preds_interx if len(pd) > 0]
        seq_data["common_preds"] = final_common_preds

        if len(final_common_preds) > 0:

            preds_str = "[ "
            skips = set()
            for pi in final_common_preds:
                if isinstance(pi, tuple):
                    preds_str += colored("{}".format(pi), "green") + ","
                else:
                    preds_str += "{}".format(pi) + ","
            preds_str = preds_str[:-1] + " ]"

            print "{}: {} {} {} \n\t{}".format(colored(fp_curr, "yellow"), inter_sects, seq_data["earliest_pos"],
                                               seq_data["preds"], preds_str)
    for x in to_delete:
        del full_preds[x]



def find_best_input(full_preds, jdata):
    results = []
    proc_cnt =0
    for fp_curr, seq_data in sorted(full_preds.items(), key=lambda x: x[1]["earliest_pos"]):
        best_bytes = None
        best_bytes_sep = []
        run_index = 0
        best_run = -100
        proc_cnt += 1

        goal_ending = seq_data["train"]

        for run in jdata:
            run_preds = []
            run_bytes = bytearray([])
            node_index = 0
            run_bytes_sep = []
            complete = False
            seq_index = 0
            preds_interx = list(seq_data["common_preds"])
            run_hashes = [x["hash_bb"] for x in run]
            #if proc_cnt == 6 and fp_curr in run_hashes:
                #print("{} {} {}".format(fp_curr, seq_data, goal_ending))
                #ipdb.set_trace()
                #IPython.embed()

            #print (preds_interx)
            run_hashes = [ x["hash_bb"] for x in run ]

            # if this fp not in this run, we dont' care about it right now, skip it
            if fp_curr not in run_hashes:
                continue

            goal_pos = run_hashes.index(fp_curr)
            # start from top, b/c really looking for HEADs which occur at end of train
            for run_index in reversed(range(0, goal_pos - len(goal_ending)+1)):
                run_data = run[run_index]
                rhash = run_data["hash_bb"]

                # Trains get priority
                # if rhash is a HEAD value and that value is in the group of common predecessors then added the input
                if rhash in full_preds :
                    s_train = full_preds[rhash]["train"]
                    if s_train in preds_interx:
                        # start with MinionX to keep run_bytes order
                        for train_index in range(0, len(s_train)):
                            train_run_index = run_index - (len(s_train) - train_index -1)
                            train_run_data = run[train_run_index]
                            run_bytes.extend(bytearray(b64decode(train_run_data ["input"])))
                            run_bytes_sep.append({"bytes": bytearray(b64decode(train_run_data ["input"])),
                                                  "hash": train_run_data ["hash_bb"],
                                                  "group": "Minion"})
                        run_bytes_sep[-1]["group"] = "HEAD"
                        preds_interx.remove(s_train)
                        continue

                # if not a train and exists in preds_interx
                if rhash in preds_interx:
                    run_bytes.extend(bytearray(b64decode(run_data["input"])))
                    run_bytes_sep.append({"bytes": bytearray(b64decode(run_data["input"])), "hash": rhash})
                    preds_interx.remove(rhash)


            # everything was found, add the goal ending train
            if len(preds_interx) == 0:
                for gindex in range(0, len(goal_ending)):
                    gtrain_run_index = goal_pos - (len(goal_ending) - gindex - 1)
                    gtrain_run_data = run[gtrain_run_index]
                    run_bytes.extend(bytearray(b64decode(gtrain_run_data["input"])))
                    run_bytes_sep.append({"bytes": bytearray(b64decode(gtrain_run_data["input"])),
                                          "hash": gtrain_run_data["hash_bb"],
                                          "group": "Minion"})
                run_bytes_sep[-1]["group"] = "TOP_HEAD"

            if run_bytes is not None and len(run_bytes) > 0 and len(preds_interx) == 0:
                if best_bytes is None:
                    best_bytes = run_bytes
                    best_run = run_index
                elif len(run_bytes) < len(best_bytes):
                    best_bytes = run_bytes
                    best_run = run_index
                best_bytes_sep = run_bytes_sep

        # str_out = "".join(map(chr, run_bytes))
        if best_bytes is None:
            cprint ("{} Nothing found for {} {}".format(proc_cnt, fp_curr, seq_data), "red")

        if best_bytes is not None:

            # new_best_run_sep = normalize_input(best_run_sep)
            #
            # best_bytes = bytearray([])
            # for x in new_best_run_sep:
            #     best_bytes.extend(x)

            print("{} {} isecs={} size={} len(inp)={} runid={}\n\t{}\t\n{}\n"
                  .format(1, 1, 1, len(preds_interx), len(best_bytes), best_run, preds_interx,
                          repr(best_bytes)))
            for x in best_bytes_sep:
                if "group" in x:
                    cprint("{}".format(x), "yellow")
                # else:
                #     print("{}".format(x))
            print("*" * 70)
            results.append(best_bytes_sep)
            # out_bytes.append(best_bytes)

            # len_sum = 0
            # for x in bytes_sep:
            #     len_sum += len(x)
            # avg_len = len_sum / len(bytes_sep)
            #
            # for i in range(0, len(bytes_sep)):
            #     if len(bytes_sep[i]) > avg_len:

    return results

if __name__ == "__main__":
    AUTO_SEED_RESULTS = "/project/auto_seed_results"
    repeated_input(j)

    full_preds = find_links(j)

    find_mandatory_pred(full_preds, j)
    # not found

    found = False
    out=[]
    # for row in j:
    #     for row_index in range(0, len(row)-3):
    #         row_data = row[row_index]
    #         if row[row_index]["hash_bb"] == find_me[0]:
    #             out.append([row[row_index]["hash_bb"], row[row_index+1]["hash_bb"], row[row_index+2]["hash_bb"]])
    #         #if row[row_index]["hash_bb"] == find_me[0] and row[row_index+1]["hash_bb"] == find_me[1]:
    #             #IPython.embed()
    #         if row[row_index]["hash_bb"] == find_me[0] and row[row_index+1]["hash_bb"] == find_me[1] and row[row_index+2]["hash_bb"] == find_me[2]:
    #             found = True
    #             IPython.embed()

    # for val in sorted(out, key=lambda x: x[1]):
    #     cprint("{} {} {}".format(val[0],val[1],val[2]),"red")

    # if not found:
    #     raise Exception("WE HAVE A PROB")

    best_input = find_best_input(full_preds, j)
    out_bytes = bytearray([])
    output_num = 0
    grouped_bytes = []
    trains = []

    for bi in best_input:
    #for bi in best_input[len(best_input)-len(best_input)/3:]:
        curr_bytes = bytearray([])
        curr_hashes = []
        for inp_unit in bi:
            if "group" in inp_unit:
                the_bytes = inp_unit["bytes"]
                if "\x00" in the_bytes:
                    pos = the_bytes.find("\x00")
                    if pos < len(the_bytes)-1:
                        the_bytes = the_bytes[0:pos+1] + "\n"
                if len(the_bytes) != len(inp_unit["bytes"]):
                    print("{} {}".format(repr(inp_unit["bytes"]),repr(the_bytes)))
                curr_bytes.extend(the_bytes)
                trains.append(the_bytes)

        grouped_bytes.append(curr_bytes)
        out_bytes = bytearray(curr_bytes)
        for j in range(0, random.randint(0, 10)):
            out_bytes.extend(out_bytes)

        open(AUTO_SEED_RESULTS + "/res{}".format(output_num), "wb").write(out_bytes)
        output_num += 1


    items = list(range(0, len(grouped_bytes)))
    print "LEN={}".format(len(out_bytes))
    for x in range(0, 100):
        random.shuffle(items)
        curr_bytes = bytearray([])
        for i in items:
            for j in range(0, random.randint(1,5)):
                curr_bytes.extend(grouped_bytes[i])
        open(AUTO_SEED_RESULTS + "/random{}".format(x), "wb").write(curr_bytes)

    items = list(range(0, len(trains)))
    print "LEN={}".format(len(out_bytes))
    for x in range(0, 100):
        random.shuffle(items)
        curr_bytes = bytearray([])
        for i in range(0, random.randint(0,len(items)-1)):
            for j in range(0, random.randint(0,10)):
                curr_bytes.extend(trains[items[i]])
        open(AUTO_SEED_RESULTS + "/random{}".format(x+100), "wb").write(curr_bytes)


