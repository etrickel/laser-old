#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import IPython as IPython
import logging
import ipdb
import glob
from tqdm import tqdm
import json
from os.path import exists, basename, join
import angr
import tracer
from termcolor import colored, cprint
# from . import config
from base64 import b64encode, b64decode

l = logging.getLogger("driller.drill_me")
#l.setLevel("DEBUG")
DEBUG = l.getEffectiveLevel() == 10

read_addrs = set()

def RepresentsInt(s):
    try:
        int(s)
        return True
    except ValueError:
        return False

def _set_concretizations(state):
    if state.project.loader.main_object.os == 'cgc':
        flag_vars = set()
        for b in state.cgc.flag_bytes:
            flag_vars.update(b.variables)

        state.unicorn.always_concretize.update(flag_vars)

    # Let's put conservative thresholds for now.
    state.unicorn.concretization_threshold_memory = 50000
    state.unicorn.concretization_threshold_registers = 50000


def hook_call(state):
    if state.mem[state.addr].int.concrete == 0x3b8:
        state.globals["set_read"] = True
        block = p.factory.block(state.addr)
        block.pp()
        print("-" * 70)

        ipdb.set_trace()

        print(hex(state.callstack.current_return_target))
        print(state.mem[state.regs.esp + 0x04].deref.string.concrete)
        # state.globals["set_ret_addr"] = state.callstack.current_return_target
        # state.globals["block_addr"] = state.addr
found = False
def hook_bb(state):
    global input_track, found

    if len(input_track) > 0:
        if "bb" in input_track[len(input_track) - 1]:
            input_track[len(input_track) - 1]["bb"].add(state.addr)
            # print hex(state.addr)
        else:
            input_track[len(input_track) - 1]["bb"] = set()
            input_track[len(input_track) - 1]["bb"].add(state.addr)
        if state.addr in input_track[len(input_track) - 1]["return_addrs"]:
            input_track[len(input_track) - 1]["curr_return_level"] += 1


def hook_exit(state):

    if state.globals["set_read"] == True:
        block = p.factory.block(state.addr)
        block.pp()
        print("-"*70)
        # if single instruction in BB thats a return
        if block.instructions == 1 and block.capstone.insns[0].mnemonic == "ret":
            ipdb.set_trace()
            entered_value = state.mem[state.regs.esp + 0x08].deref.string.concrete
            if len(entered_value) > 0:
                #print("\tEV(unfilt)={}".format(repr(entered_value)))
                entered_value = entered_value[:-1] # cutting off \x01
                #print("\t\tEV(filt)={}".format(repr(entered_value)))

            #print("B4 Return {:x} {} {}".format(state.addr, state.regs.esp, entered_value))
            stack = state.callstack
            return_addrs = []
            while stack is not None:
                if stack.current_return_target > 0:
                    return_addrs.append(stack.current_return_target)
                #print ("\t{:x} {:x}".format(stack.func_addr, stack.current_return_target))
                stack = stack.next

            if len(input_track) == 0:
                input_track.append({'return_addrs': return_addrs, "input": entered_value, "bb": set(),
                                    "prev_return_level": -1, "curr_return_level": 0})
                #print("\tfirstEV={}, RL(cur/prev)={}/{}".format(repr(entered_value), -1, 0))
            else:
                last = input_track[len(input_track) -1]
                same_return_path = True
                if len(last["return_addrs"]) == len(return_addrs):
                    for i in range(0, len(return_addrs)):
                        if last["return_addrs"][i] != return_addrs[i]:
                            same_return_path = False
                            break
                    if same_return_path:
                        if last["prev_return_level"] == -1:
                            last["prev_return_level"] = last["curr_return_level"]
                        elif last["prev_return_level"] != last["curr_return_level"]:
                            same_return_path = False
                else:
                    same_return_path = False
                prevRL = input_track[len(input_track) - 1]["prev_return_level"]
                currRL = input_track[len(input_track) - 1]["curr_return_level"]
                prior_text = input_track[len(input_track) - 1]["input"]

                if same_return_path:

                    input_track[len(input_track)-1] = {'return_addrs': return_addrs, "input": prior_text + entered_value,
                                                       "bb": set(), "prev_return_level": prevRL, "curr_return_level": 0}
                    #print("\tEV={}, RL(cur/prev)={}/{} rets={}".format(repr(temp["input"]), currRL, prevRL, map(hex,temp["return_addrs"])))
                else:
                    #print("\tnewEV={}, PriorIT={}, RL(cur/prev)={}/{}".format(repr(entered_value), repr(prior_text), currRL, prevRL))
                    print("\tPriorIT={}, RL(cur/prev)={}/{}, #bb={}".format(repr(prior_text), currRL, prevRL, len(last["bb"])))
                    input_track.append({'return_addrs': return_addrs, "input": entered_value, "bb": set(),
                                        "prev_return_level": -1, "curr_return_level": 0})

            # print input_track

            # import ipdb
            # ipdb.set_trace()

            state.globals["set_read"] = False

def exec_binary(binary, pinput, input_track):
    '''
    Asks angr, politely, to simulate execution of the binary using the given input. It currently relies on breakpoints
    to find the "receive" sys call and track the results from it.
    :param binary:
    :type binary:
    :param pinput:
    :type pinput:
    :param input_track:
    :type input_track:
    :return:
    :rtype:
    '''
    global p
    r = tracer.qemu_runner.QEMURunner(binary, pinput)
    print ("Received results from QEMU runner {}".format(len(r.trace)))

    p = angr.Project(binary)

    # for addr, proc in _hooks.items():
    #     p.hook(addr, proc)
    #     l.debug("Hooking %#x -> %s...", addr, proc.display_name)

    if p.loader.main_object.os == 'cgc':
        p.simos.syscall_library.update(angr.SIM_LIBRARIES['cgcabi_tracer'])

    s = p.factory.tracer_state(input_content=pinput, magic_content=r.magic)
    s.globals["set_read"] = False

    #s.inspect.b("mem_write", when=angr.BP_AFTER, action=debug_func)
    s.inspect.b("irsb", when=angr.BP_AFTER, action=hook_bb)
    s.inspect.b("call", when=angr.BP_AFTER, action=hook_call)
    s.inspect.b("instruction", when=angr.BP_AFTER, action=hook_exit)

    simgr = p.factory.simgr(s, save_unsat=True, hierarchy=False, save_unconstrained=r.crash_mode)

    # pushing through the concrete values to get trace

    t = angr.exploration_techniques.Tracer(trace=r.trace)
    #c = angr.exploration_techniques.CrashMonitor(trace=r.trace, crash_mode=r.crash_mode, crash_addr=r.crash_addr)
    #core = angr.exploration_techniques.DrillerCore(trace=r.trace)

    # simgr.use_technique(c)
    simgr.use_technique(t)
    #simgr.use_technique(angr.exploration_techniques.Oppologist())
    #simgr.use_technique(core)

    #print(">>> Starting steps")
    while simgr.active and simgr.one_active.globals['bb_cnt'] < len(r.trace):
        simgr.step()



def compare_bbs(bba, bbb):
    in_a = bba['input']
    bb_in_a = bba['bb']
    in_b = bbb['input']
    bb_in_b = bbb['bb']
    if bb_in_a == bb_in_b:
        cprint("\tMatched ALL {} Inputs: {} {}".format(len(bb_in_a), repr(in_a), repr(in_b)), 'green')
    else:
        print("\tFailed complete match Inputs: {} {}, # of diffs {}, sizes: {} {}"
              .format(repr(in_a), repr(in_b), len(bb_in_a - bb_in_b), len(bb_in_a), len(bb_in_b)))



l = logging.getLogger("driller.driller")#.setLevel('DEBUG')

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shellphish fuzzer interface")
    parser.add_argument('binary', help="the path to the target binary to fuzz")
    parser.add_argument('results', nargs='?', help="the path to the driller results (folder with sync)", default="")
    parser.add_argument('-i','--input', help="The logging configuration file.", default="")
    args = parser.parse_args()

    afl_results = args.results
    user_input = args.input

    binary = args.binary #"/project/cgc_samples/cqe-challenges/CROMU_00001/chat"
    #pinput = "1\nTUB\n1\nGAR\n1\nMARBOL\n3\n"

    if not exists(binary):
        print("Binary does not exist")
        exit(22)

    # Used for debugging
    if len(user_input) > 0:
        user_input = user_input.decode('string_escape')
        input_track = []
        exec_binary(binary, user_input, input_track)
        ipdb.set_trace()

        exit(0)

    if not exists(afl_results) or not exists(join(afl_results,"sync")):
        print("Either a valid AFL results directory containing the 'sync' folder must be provided or the --input option must be used")
        exit(23)

    total_input_track = []

    if exists("results.json"):
        with open("results.json", "r") as jf:
            total_input_track = json.load(jf)

    ext_dirs = glob.iglob(afl_results + "/sync/fuzzer-*/queue/*")

    # force generation and put into list for tqdm
    list_dirs = []
    for cex_report in ext_dirs:
        list_dirs.append(cex_report)

    for i in tqdm(range(2000, len(list_dirs)), desc="Inputs"):
        processed_inputs = set()
        # tracks input patterns already processed to avoid duplication
        if exists("processed.dat"):
            arr_processed = open("processed.dat", "rb").read().split("\n")
            for afile in arr_processed:
                processed_inputs.add(afile)

        pinput = open (list_dirs[i], "r").read()

        if repr(pinput) in processed_inputs:
            continue
        if len(pinput) < 5 or len(pinput) > 300:
            continue

        open("processed.dat", "ab").write(repr(pinput) + "\n")

        print("Reading from {}".format(basename(list_dirs[i])))
        print("Input Length={}".format(len(pinput)))

        input_track = []
        exec_binary(binary, pinput, input_track)

        # drill_old(binary,pinput)

        new_ipt = []
        for ipt in input_track:
            bb_hashval = hash(frozenset(ipt["bb"]))
            new_ipt.append({"input": b64encode(ipt["input"]), "hash_bb": bb_hashval})

        total_input_track.append(new_ipt)

        if DEBUG:
            temp = total_input_track[len(total_input_track) - 1]
            for item in temp:
                item["input"] = repr(b64decode(item["input"]))
            # ipdb.set_trace()
            IPython.embed()
            exit(99)

        with open("results.json", "w") as jf:
            json.dump(total_input_track, jf)

        open("processed.dat", "ab").write(repr(pinput) + "\n")

