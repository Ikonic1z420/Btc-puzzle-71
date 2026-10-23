#!/usr/bin/env python3
"""Puzzle 71 identity auditor + real CPU ECC/HASH160 integrity canary.

This does not discover or manufacture a Puzzle 71 public key. The production
canary scans exactly 100,000,000 synthetic keys, in two disjoint directions,
with independent ECC/HASH160 integrity checks at every 1,000,000 committed keys.
Only this precise geometry is eligible for a technical canary PASS. No GPU
work is performed, and no public-key identity gate is automatically passed.

Requires: cryptography (independent ECC verifier); coincurve optional for fast
secp256k1 incremental point steps. Uses p71_manifest_controller.py for Base58,
SHA256/RIPEMD160, atomic writes, and ECC verification.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import multiprocessing as mp
import os
from pathlib import Path
import queue
import sys
import time

import p71_manifest_controller as core

CANARY_START = core.CANARY_START
CANARY_SIZE = 100_000_000
INTEGRITY_INTERVAL = 1_000_000
MARKS = 100
CONTROL_PRIVATE = CANARY_START + CANARY_SIZE + 13  # NEVER IN THE SCANNED RANGE
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
GENESIS = hashlib.sha256(b'P71_REAL_ECC_HASH160_CANARY_V2').hexdigest()
MILESTONE_COLUMNS = ['timestamp','direction','segment_index','range_first_hex',
    'range_last_hex','keys_hashed','total_committed','anchor_first_hash160',
    'anchor_mid_hash160','anchor_last_hash160','worker_chain_sha256',
    'checkpoint_sha256','elapsed_seconds','engine','integrity_result']


def point_add(a, b):
    """Slow, independent secp256k1 reference math. For samples only."""
    if a is None: return b
    if b is None: return a
    x1,y1 = a; x2,y2 = b
    if x1 == x2 and (y1 + y2) % P == 0: return None
    if a == b:
        if y1 == 0: return None
        slope = (3*x1*x1 * pow(2*y1,-1,P)) % P
    else:
        slope = ((y2-y1) * pow((x2-x1) % P, -1, P)) % P
    x3 = (slope*slope - x1 - x2) % P
    return (x3, (slope*(x1-x3) - y1) % P)


def reference_point(priv):
    if not 1 <= priv < core.CURVE_N: raise ValueError('Invalid scalar')
    q, a = None, (GX, GY)
    while priv:
        if priv & 1: q = point_add(q,a)
        a = point_add(a,a)
        priv >>= 1
    if q is None: raise ValueError('Point at infinity')
    x,y = q
    if (y*y - x*x*x - 7) % P: raise ValueError('Point off curve')
    return q


def reference_pubkey(priv):
    x,y = reference_point(priv)
    return bytes([2+(y&1)]) + x.to_bytes(32,'big')


def reference_hash160(priv):
    own = reference_pubkey(priv)
    # Cross-check against an entirely independent OpenSSL-backed implementation.
    if own != core.compressed_key(priv, 'cryptography'):
        raise RuntimeError('Independent ECC implementations disagree on sampled key')
    return core.hash160(own).hex()


def check_identity(pubhex=None):
    target = core.decode_p2pkh(core.PUZZLE_ADDRESS).hex()
    if target != core.EXPECTED_HASH160:
        raise ValueError('Canonical Puzzle 71 address HASH160 mismatch')
    result = {
        'address': core.PUZZLE_ADDRESS,
        'address_checksum_valid': True,
        'address_hash160': target,
        'full_public_key_established': False,
        'candidate_public_key': pubhex,
        'candidate_valid_curve_point': None,
        'candidate_hash160': None,
        'candidate_matches_address': False,
    }
    if pubhex is not None:
        try:
            pk = bytes.fromhex(pubhex)
            if len(pk) != 33 or pk[0] not in (2,3):
                raise ValueError('Expected a 33-byte compressed public key (02/03)')
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(),pk)
            result['candidate_valid_curve_point'] = True
            result['candidate_hash160'] = core.hash160(pk).hex()
            result['candidate_matches_address'] = result['candidate_hash160'] == target
            result['full_public_key_established'] = result['candidate_matches_address']
        except (ValueError, TypeError) as ex:
            result['candidate_valid_curve_point'] = False
            result['candidate_error'] = str(ex)
    return result


def control_identity():
    """Prove canary identity with TWO different ECC implementations and fixed G."""
    if reference_pubkey(1).hex() != ('0279be667ef9dcbbac55a06295ce870b07029bfcd'
                                      'b2dce28d959f2815b16f81798'):
        raise RuntimeError('Independent secp256k1 generator vector failed')
    if reference_hash160(1) != '751e76e8199196d454941c45d1b3a323f1433bd6':
        raise RuntimeError('Independent HASH160 test vector failed')
    compressed = reference_pubkey(CONTROL_PRIVATE)
    other = core.compressed_key(CONTROL_PRIVATE,'cryptography')
    if compressed != other:
        raise RuntimeError('Independent ECC engines disagree for known-key control')
    target = core.hash160(compressed)
    # Positive detection, in both directions, with known target IN tiny range.
    for step, first, last in ((1,CONTROL_PRIVATE-7,CONTROL_PRIVATE+7),
                              (-1,CONTROL_PRIVATE+7,CONTROL_PRIVATE-7)):
        scanned, hit = core.scan_batch(first,last,step,15,target,'cryptography')
        if hit != CONTROL_PRIVATE or scanned != 8:
            raise RuntimeError('Known-key positive HASH160 scan failed')
    return {
        'kind':'SYNTHETIC_CANARY_CONTROL_NOT_PUZZLE_71_PUBKEY',
        'public_key_compressed':compressed.hex(),
        'hash160':target.hex(),
        'secret_outside_scanned_interval':True,
        'positive_match_test_both_directions':True,
        'independent_secp256k1_checked':True,
    }


def make_geometry(total, interval):
    if total <= 0 or interval <= 0 or total % (2*interval):
        raise ValueError('Total must be divisible by 2 * integrity interval')
    a = CANARY_START
    end = a + total - 1
    halves = core.split_chunk(a,end)
    return {name:{'first':first,'last':last,'step':step,
                  'segment_count':(abs(last-first)+1)//interval}
            for name,(first,last,step) in halves.items()}


def initial_state(total, interval, engine, control):
    geometry = make_geometry(total,interval)
    workers = {d:{'segments':0,'processed':0,'chain_sha256':GENESIS} for d in geometry}
    spec = {'mode':'production' if total == CANARY_SIZE and interval == INTEGRITY_INTERVAL else 'demo',
            'start':f'{CANARY_START:x}','end':f'{CANARY_START+total-1:x}',
            'total':total,'interval':interval,'geometry':geometry,
            'control_pubkey': control['public_key_compressed'],
            'control_hash160':control['hash160']}
    return {'schema':2,'spec':spec,'spec_sha256':core.checksum(spec),
            'engine':engine,
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'workers':workers,'milestones':[],
            'created_at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
            'tech_canary_passed':False,'full_p71_pubkey_established':False}


def sample_keys(start,step,interval):
    return (start, start + (interval//2)*step, start+(interval-1)*step)


def segment_scan(first,step,count,target_hex,engine):
    """Real CPU ECC and HASH160 for every key, with samples from SCANNED hashes."""
    if not 1 <= first < core.CURVE_N or not 1 <= first+(count-1)*step < core.CURVE_N:
        raise ValueError('Segment outside secp256k1 scalar range')
    samples = (0,count//2,count-1)
    sample_hashes = {}
    target = bytes.fromhex(target_hex)
    if engine == 'coincurve':
        from coincurve import PublicKey
        point = PublicKey.from_valid_secret(first.to_bytes(32,'big'))
        delta = (1 if step == 1 else core.CURVE_N-1).to_bytes(32,'big')
        for i in range(count):
            h = core.hash160(point.format(compressed=True))
            if i in samples: sample_hashes[str(i)] = h.hex()
            if h == target: return {'hit':first+i*step, 'count':i+1,'samples':sample_hashes}
            if i+1 < count: point.add(delta, update=True)
    elif engine == 'python-step':
        # Much faster than one OpenSSL scalar multiplication per candidate.
        # Derive the first point once, then reuse (k +/- 1)G = kG +/- G.
        point = reference_point(first)
        delta = (GX, GY if step == 1 else (-GY) % P)
        for i in range(count):
            x,y = point
            h = core.hash160(bytes([2+(y&1)]) + x.to_bytes(32,'big'))
            if i in samples: sample_hashes[str(i)] = h.hex()
            if h == target: return {'hit':first+i*step,'count':i+1,'samples':sample_hashes}
            if i+1 < count: point = point_add(point,delta)
    elif engine == 'cryptography':
        for i in range(count):
            k = first + i*step
            h = core.hash160(core.compressed_key(k,'cryptography'))
            if i in samples: sample_hashes[str(i)] = h.hex()
            if h == target: return {'hit':k,'count':i+1,'samples':sample_hashes}
    else:
        raise ValueError('Unknown ECC engine')
    return {'hit':None,'count':count,'samples':sample_hashes}


def worker_main(direction, geom, interval, target_hex, engine, start_segment, out, ack):
    try:
        for idx in range(start_segment,geom['segment_count']):
            start = geom['first']+idx*interval*geom['step']
            t0=time.perf_counter()
            r=segment_scan(start,geom['step'],interval,target_hex,engine)
            out.put({'direction':direction,'index':idx+1,'first':start,
                     'last':start+(interval-1)*geom['step'],
                     'result':r,'elapsed_seconds':time.perf_counter()-t0})
            if ack.get() != 'continue': return
    except BaseException as e:
        out.put({'direction':direction,'error':repr(e)})


def expected_milestone(state, msg):
    spec=state['spec']; direction=msg['direction']
    geom=spec['geometry'][direction]; w=state['workers'][direction]
    idx=w['segments']+1
    n=spec['interval']; first=geom['first']+(idx-1)*n*geom['step']
    last=first+(n-1)*geom['step']
    if (msg['index'],msg['first'],msg['last']) != (idx,first,last):
        raise RuntimeError('Worker interval, direction or checkpoint order mismatch')
    r=msg['result']
    if r['hit'] is not None: raise RuntimeError('Unexpected target match inside negative control interval')
    if r['count'] != n: raise RuntimeError('Worker failed to ECC+HASH160 all million keys')
    expected={str(i):reference_hash160(first+i*geom['step']) for i in (0,n//2,n-1)}
    if r['samples'] != expected:
        raise RuntimeError('Independent sample ECC/HASH160 verification FAILED')
    return first,last,expected


def milestone_payload(direction,index,first,last,n,expected,prior_chain):
    return {'direction':direction,'index':index,'first_hex':f'{first:x}',
            'last_hex':f'{last:x}','keys_hashed':n,
            'anchors':expected,'previous_chain_sha256':prior_chain}


def compute_chain(payload):
    return hashlib.sha256(bytes.fromhex(payload['previous_chain_sha256']) + core.json_bytes(payload)).hexdigest()


def validate_checkpoint(state):
    spec=state['spec']
    if state['source_sha256'] != hashlib.sha256(Path(__file__).read_bytes()).hexdigest():
        raise ValueError('Canary program changed since checkpoint; source must be restored or independently re-audited')
    if state['schema'] != 2 or state['spec_sha256'] != core.checksum(spec):
        raise ValueError('Corrupt canary specification')
    total,interval=spec['total'],spec['interval']
    if spec['geometry'] != make_geometry(total,interval):
        raise ValueError('Invalid canary range geometry')
    if state['full_p71_pubkey_established'] is not False:
        raise ValueError('A canary cannot establish an unknown Puzzle 71 public key')
    c = control_identity()
    if spec['control_hash160'] != c['hash160'] or spec['control_pubkey'] != c['public_key_compressed']:
        raise ValueError('Canary synthetic control identity was altered')
    seen={d:0 for d in spec['geometry']}; chains={d:GENESIS for d in seen}
    for m in state['milestones']:
        d=m['payload']['direction']
        if d not in seen: raise ValueError('Unknown worker in milestone history')
        seen[d]+=1; idx=seen[d]
        geom=spec['geometry'][d]
        if idx > geom['segment_count']: raise ValueError('Too many milestone checks')
        first=geom['first']+(idx-1)*interval*geom['step']
        last=first+(interval-1)*geom['step']
        expected={str(i):reference_hash160(first+i*geom['step']) for i in (0,interval//2,interval-1)}
        payload=milestone_payload(d,idx,first,last,interval,expected,chains[d])
        if m['payload'] != payload or compute_chain(payload) != m['chain_sha256']:
            raise ValueError(f'Integrity history failed at {d} segment {idx}')
        chains[d]=m['chain_sha256']
    for d,w in state['workers'].items():
        if w['segments'] != seen[d] or w['processed'] != seen[d]*interval or w['chain_sha256'] != chains[d]:
            raise ValueError(f'Corrupt progress for {d}')
    complete=(sum(w['processed'] for w in state['workers'].values()) == total and
              len(state['milestones']) == total//interval and
              all(state['workers'][d]['segments'] == spec['geometry'][d]['segment_count'] for d in seen))
    eligible = (total == CANARY_SIZE and interval == INTEGRITY_INTERVAL and spec['mode'] == 'production')
    if state['tech_canary_passed'] != (complete and eligible):
        raise ValueError('Technical pass flag disagrees with validated coverage')
    return complete and eligible


def write_artifacts(folder,state):
    rows=[]
    for m in state['milestones']:
        p=m['payload']; anchors=p['anchors']
        rows.append({'timestamp':m['timestamp'],'direction':p['direction'],
            'segment_index':p['index'],'range_first_hex':p['first_hex'],
            'range_last_hex':p['last_hex'],'keys_hashed':p['keys_hashed'],
            'total_committed':m['total_committed'],
            'anchor_first_hash160':anchors['0'],
            'anchor_mid_hash160':anchors[str(p['keys_hashed']//2)],
            'anchor_last_hash160':anchors[str(p['keys_hashed']-1)],
            'worker_chain_sha256':m['chain_sha256'],
            'checkpoint_sha256':core.checksum(state),
            'elapsed_seconds':m['elapsed_seconds'],'engine':state['engine'],
            'integrity_result':'PASS'})
    import io
    buf=io.StringIO(newline=''); writer=csv.DictWriter(buf,fieldnames=MILESTONE_COLUMNS,lineterminator='\n')
    writer.writeheader(); writer.writerows(rows)
    core.atomic_write(folder/'integrity_every_1m.csv',buf.getvalue().encode('utf-8'))
    # Preserve user's EXACT 16 column evidence header; only write COMPLETION when passed.
    ev=io.StringIO(newline=''); writer=csv.DictWriter(ev,fieldnames=core.HEADER,lineterminator='\n')
    writer.writeheader()
    if state['tech_canary_passed']:
        for slice_idx,d in enumerate(('forward','backward')):
            g=state['spec']['geometry'][d]
            milestones=[m for m in state['milestones'] if m['payload']['direction']==d]
            writer.writerow({'timestamp':milestones[-1]['timestamp'],
              'manifest_sha256':state['spec_sha256'], 'rank':1,'chunk_index':0,
              'slice_index':slice_idx,'start_hex':f"{g['first']:x}",
              'end_hex':f"{g['last']:x}",'direction':d,
              'command':'p71_integrity_canary.py run','input_file':'synthetic_known_control',
              'exit_code':0,'elapsed_seconds':f"{sum(m['elapsed_seconds'] for m in milestones):.3f}",
              'scanner_result':'complete_no_match_50m_independent_million_checks',
              'checkpoint_before_sha256':GENESIS,
              'checkpoint_after_sha256':state['workers'][d]['chain_sha256'], 'error_text':''})
    core.atomic_write(folder/'evidence.csv',ev.getvalue().encode('utf-8'))
    report={'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
        'address_identity':check_identity(),
        'canary_control_public_key':state['spec']['control_pubkey'],
        'canary_control_hash160':state['spec']['control_hash160'],
        'scanned_keys_durable':sum(w['processed'] for w in state['workers'].values()),
        'required_keys':state['spec']['total'],
        'integrity_checks':len(state['milestones']),
        'required_checks':state['spec']['total']//state['spec']['interval'],
        'canary_technical_pass':state['tech_canary_passed'],
        'puzzle71_full_public_key_identity_pass':False,
        'gpu_tuning_unlocked':False,
        'note':'Sampled checkpoints check three real scanned hashes per 1m against independent ECC; not a formal proof of every individual computation.'}
    core.atomic_write(folder/'identity_and_canary_report.json',core.json_bytes(report))


def run_canary(folder, engine, total, interval, stop_after=None):
    folder=Path(folder); folder.mkdir(parents=True,exist_ok=True)
    cp=folder/'integrity_checkpoint.json'
    control=control_identity()
    if cp.exists():
        state=json.loads(cp.read_text('utf-8'))
        if state['spec']['total'] != total or state['spec']['interval'] != interval:
            raise ValueError('State directory belongs to DIFFERENT canary geometry')
        validate_checkpoint(state)
        # Engine cannot change partway through an already started run.
        if state['engine'] != engine: raise ValueError('Engine differs from original canary')
    else:
        state=initial_state(total,interval,engine,control)
        core.atomic_write(cp,core.json_bytes(state))
    if state['tech_canary_passed']:
        print('Canary already technically passed; existing proofs validated.')
        write_artifacts(folder,state)
        return True
    write_artifacts(folder,state)
    context=mp.get_context('spawn')
    events=context.Queue(); processes={}; acks={}
    for d,g in state['spec']['geometry'].items():
        if state['workers'][d]['segments'] >= g['segment_count']: continue
        ack=context.Queue(); acks[d]=ack
        proc=context.Process(target=worker_main,args=(d,g,interval,control['hash160'],engine,
            state['workers'][d]['segments'],events,ack))
        proc.start(); processes[d]=proc
    outstanding=set(processes)
    commits=0
    try:
        while outstanding:
            try: msg=events.get(timeout=3)
            except queue.Empty:
                for d in outstanding:
                    if not processes[d].is_alive():
                        raise RuntimeError(f'{d} terminated before a durable milestone checkpoint')
                continue
            d=msg['direction']
            if d not in outstanding: raise RuntimeError('Unexpected or duplicate worker response')
            if 'error' in msg: raise RuntimeError(f'{d} scanner error: {msg["error"]}')
            first,last,anchors=expected_milestone(state,msg)
            w=state['workers'][d]; n=interval
            payload=milestone_payload(d,w['segments']+1,first,last,n,anchors,w['chain_sha256'])
            chained=compute_chain(payload)
            committed=sum(x['processed'] for x in state['workers'].values())+interval
            record={'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
                    'payload':payload,'chain_sha256':chained,
                    'total_committed':committed,'elapsed_seconds':round(msg['elapsed_seconds'],4)}
            w['segments']+=1; w['processed']+=interval; w['chain_sha256']=chained
            state['milestones'].append(record)
            state['tech_canary_passed']=(committed==total and total==CANARY_SIZE
                 and interval==INTEGRITY_INTERVAL and len(state['milestones'])==MARKS)
            core.atomic_write(cp,core.json_bytes(state))
            write_artifacts(folder,state)
            commits+=1
            print(f"INTEGRITY PASS | {d:<8} segment {w['segments']:02d}/"
                  f"{state['spec']['geometry'][d]['segment_count']:02d} | "
                  f"{committed:,}/{total:,} real hashes committed | "
                  f"sha256 {chained[:16]}...",flush=True)
            if stop_after and commits>=stop_after:
                acks[d].put('stop')
                print('Intentional test stop after durable segment; safe to resume.')
                break
            if w['segments']>=state['spec']['geometry'][d]['segment_count']:
                acks[d].put('stop'); outstanding.remove(d)
            else: acks[d].put('continue')
        if state['tech_canary_passed']:
            validate_checkpoint(state)
            write_artifacts(folder,state)
            print('TECHNICAL CANARY PASS: exactly 100,000,000 real CPU ECC+HASH160 evaluations;'
                  ' 100 independently checked million-key boundaries.')
            print('Puzzle 71 full public-key identity remains UNKNOWN; GPU promotion stays LOCKED.')
            return True
        return False
    except KeyboardInterrupt:
        print('Interrupted. Restart with same command to resume from last verified 1m segment.',file=sys.stderr)
        return False
    finally:
        for d,ack in acks.items():
            try: ack.put('stop')
            except Exception: pass
        for proc in processes.values():
            proc.join(timeout=0.5)
            if proc.is_alive(): proc.terminate(); proc.join(timeout=2)
        events.close()
        for ack in acks.values():ack.close()


def main():
    ap=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    sub=ap.add_subparsers(dest='cmd',required=True)
    identity=sub.add_parser('identity',help='Address identity; optional FULL compressed candidate public key check')
    identity.add_argument('--pubkey',default=None)
    run=sub.add_parser('run',help='Real 100-million-key CPU ECC/HASH160 canary with 100 integrity checkpoints')
    run.add_argument('--state-dir',required=True)
    run.add_argument('--engine',choices=('auto','coincurve','python-step','cryptography'),default='auto')
    run.add_argument('--stop-after',type=int,default=None,help='Diagnostic: stop after N verified million-key milestones; no technical pass')
    demo=sub.add_parser('smoketest',help='Small REAL-ECC canary, never eligible for promotion')
    demo.add_argument('--state-dir',required=True)
    demo.add_argument('--engine',choices=('auto','coincurve','python-step','cryptography'),default='auto')
    demo.add_argument('--total-keys',type=int,default=2000)
    demo.add_argument('--integrity-every',type=int,default=100)
    demo.add_argument('--stop-after',type=int,default=None,help='Fault injection: stop after N durable milestones')
    status=sub.add_parser('status',help='Verify integrity of persisted milestones and report progress')
    status.add_argument('--state-dir',required=True)
    args=ap.parse_args()
    try:
        if args.cmd=='identity':
            info=check_identity(args.pubkey)
            print(json.dumps(info,indent=2))
            return 0 if args.pubkey is None or info['candidate_matches_address'] else 2
        if args.cmd=='status':
            folder=Path(args.state_dir)
            state=json.loads((folder/'integrity_checkpoint.json').read_text('utf-8'))
            passed=validate_checkpoint(state)
            write_artifacts(folder,state)
            print(f"Technical canary: {'PASS' if passed else 'NOT PASSED'}")
            print('P71 full pubkey identity: NOT ESTABLISHED | GPU tuning: LOCKED')
            for d,w in state['workers'].items():
                print(f"{d}: {w['segments']} integrity segments, {w['processed']:,} keys")
            return 0 if passed else 2
        if args.engine == 'auto':
            try:
                engine=core.engine_name('coincurve')
            except RuntimeError:
                engine='python-step'
        elif args.engine == 'python-step':
            engine='python-step'
        else:
            engine=core.engine_name(args.engine)
        total,interval=(CANARY_SIZE,INTEGRITY_INTERVAL) if args.cmd=='run' else (args.total_keys,args.integrity_every)
        result=run_canary(args.state_dir,engine,total,interval,getattr(args,'stop_after',None))
        return 0 if result else 2
    except (ValueError,RuntimeError,OSError,KeyError,ImportError,TypeError) as exc:
        print('ERROR:',str(exc),file=sys.stderr)
        return 1


if __name__=='__main__':
    mp.freeze_support()
    sys.exit(main())
