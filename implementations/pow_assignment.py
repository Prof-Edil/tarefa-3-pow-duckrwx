#!/usr/bin/env python3
import csv
import hashlib
import heapq
from pathlib import Path

WEIGHT_LIMIT = 4_000_000
REQUIRED_TXID = '4c50e3dad7f98bceb6441f96b23748dea84fbdb7cedd603441e6ea4a574d04a6'
TARGET_TXID = '49ff8cccf1ca12179e9ae7a4760f550b5a18401b27e1e057604e27c3e10c08fb'
PREVIOUS_BLOCK = '00000000d1145790a8694403d4063f323d499e655c83426834d4ce2f8dd4a2ee'
MERKLE_ROOT = 'c0a692de10b69e2381a2856dcb0d0736dcd307bf25af7ce74831bf25793de626'
TARGET = int('00000000ffff0000000000000000000000000000000000000000000000000000', 16)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def select_transactions():
    mempool = {}
    children = {}
    with open('data/mempool.csv', newline='') as f:
        for row in csv.reader(f):
            txid = row[0].strip().lower()
            parents = [p.strip().lower() for p in row[3].split(';') if p.strip()] if len(row) > 3 and row[3].strip() else []
            mempool[txid] = {'fee': int(row[1]), 'weight': int(row[2]), 'parents': parents}
            for p in parents:
                children.setdefault(p, []).append(txid)

    remaining = {tx: set(v['parents']) for tx, v in mempool.items()}
    available = []
    for tx, v in mempool.items():
        if not remaining[tx]:
            heapq.heappush(available, (-(v['fee'] / v['weight']), -v['fee'], tx))

    selected, selected_set = [], set()
    weight = 0
    while available:
        _, _, tx = heapq.heappop(available)
        if tx in selected_set:
            continue
        if weight + mempool[tx]['weight'] <= WEIGHT_LIMIT:
            selected.append(tx)
            selected_set.add(tx)
            weight += mempool[tx]['weight']
            for child in children.get(tx, []):
                remaining[child].discard(tx)
                if not remaining[child]:
                    v = mempool[child]
                    heapq.heappush(available, (-(v['fee'] / v['weight']), -v['fee'], child))

    def ancestor_order(txid, seen=None, out=None):
        if seen is None:
            seen, out = set(), []
        if txid in seen:
            return out
        seen.add(txid)
        for p in mempool[txid]['parents']:
            ancestor_order(p, seen, out)
        out.append(txid)
        return out

    required_chain = ancestor_order(REQUIRED_TXID)
    if not all(tx in selected_set for tx in required_chain):
        extra_weight = sum(mempool[tx]['weight'] for tx in required_chain if tx not in selected_set)
        while weight + extra_weight > WEIGHT_LIMIT:
            tx = selected.pop()
            if tx in required_chain:
                selected.insert(0, tx)
                break
            selected_set.remove(tx)
            weight -= mempool[tx]['weight']

        rebuilt, rebuilt_set = [], set()
        for tx in required_chain:
            rebuilt.append(tx)
            rebuilt_set.add(tx)
        for tx in selected:
            if tx not in rebuilt_set and all(p in rebuilt_set for p in mempool[tx]['parents']):
                rebuilt.append(tx)
                rebuilt_set.add(tx)
        selected = rebuilt
        selected_set = set(selected)

    assert REQUIRED_TXID in selected_set
    Path('solutions/exercise01.txt').write_text('\n'.join(selected) + '\n')


def merkle_and_proof():
    txids = [x.strip().lower() for x in Path('data/ex02_txid_list.txt').read_text().splitlines() if x.strip()]
    idx = txids.index(TARGET_TXID)
    level = [bytes.fromhex(x) for x in txids]
    proof = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        proof.append(level[idx ^ 1].hex())
        level = [sha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        idx //= 2
    Path('solutions/exercise02.txt').write_text('\n'.join([level[0].hex()] + proof) + '\n')


def mine_header():
    version = (2).to_bytes(4, 'big')
    previous = bytes.fromhex(PREVIOUS_BLOCK)
    merkle = bytes.fromhex(MERKLE_ROOT)
    timestamp = (1231000000).to_bytes(4, 'big')

    for nonce in range(0, 1 << 32):
        header = version + previous + merkle + timestamp + nonce.to_bytes(8, 'big')
        h = sha256(header)
        if int.from_bytes(h, 'big') <= TARGET:
            Path('solutions/exercise03.txt').write_text(header.hex() + '\n')
            print('nonce', nonce)
            print('hash', h.hex())
            return
    raise RuntimeError('nonce not found')


if __name__ == '__main__':
    select_transactions()
    merkle_and_proof()
    mine_header()
