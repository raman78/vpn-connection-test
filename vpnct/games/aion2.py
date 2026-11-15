"""Read three messages from the AION 2 server's stream, and nothing else.

The game's own ping, loading screens and the server's clock are in the
server's messages, not in packet timing: `Ping_RS` echoes the time the game
sent its ping request, `PrepareEnterMap_NT` starts every loading screen,
and `MapFrame_NT` carries the server's time about 20 times a second. Every
other message, chat included, is stepped over by its length without being
read.

Stream format (as Questlog reads it, `docs/ARCHITECTURE.md` §4a):

    frame   = length:varint  opcode:u16le  body
    length  = the frame's size + (4 - size of the varint)
    opcode 0xFFFF is a bundle: body = raw_size:u32le  lz4_block,
    which unpacks to further frames.

A stream is *recognised* once RECOGNISE_AFTER messages in a row decode
exactly as one of the known messages; until then nothing is reported, so a
stream that only happens to look framed is never read as the game's. A
stream that is not recognised within GIVE_UP_BYTES is given up.

The game's ping (`GameConnection`): `Ping_RS` carries the game's clock at
the moment it sent the request (ms, not our clock: under Wine it differed
from the wall clock by a constant). The request is the game's REQUEST_LEN
data packet, sent every 10 s; the wall-clock time of that packet minus the
echoed clock is the offset between the two clocks. Measured 2026-11-15 over
28 pairs it varied by ±1.2 ms (the clock's 1 ms steps). The offset is the
median over the last OFFSET_SAMPLES pairs, so a pair matched wrongly (a
reply packed in a bundle, after which the next request is paired with the
wrong reply) cannot move it; every reply then gets a ping, arrival minus
the request's time on our clock — the same value Questlog shows, to 2 ms.
The clock belongs to the game process, not to a server, so a new server
connection starts from the previous connection's offsets (`seed`), once
its first pair agrees with them within SEED_AGREE_MS; then its pings count
from the first reply, not after OFFSET_MIN pairs. A first pair that
disagrees (the game was restarted) drops the seed.
"""

from __future__ import annotations

import statistics
import struct
from collections import deque
from dataclasses import dataclass, field

OP_MAP_FRAME = 13824        # MapFrame_NT: serverTime i64
OP_PING_RS = 13827          # Ping_RS: result u16, clientSentTime i64, serverGameClock i64
OP_ENTER_MAP = 13857        # PrepareEnterMap_NT: enterMapTicket i32, mapId i32, ...
OP_BUNDLE = 0xFFFF
MAX_FRAME = 65536
RECOGNISE_AFTER = 3
GIVE_UP_BYTES = 262144


@dataclass(frozen=True)
class Message:
    at: float               # arrival of the packet that completed it, epoch seconds
    kind: str               # "ping" | "map" | "frame"
    value: int              # clientSentTime | mapId | serverTime


def varint(buf: bytes, pos: int, end: int) -> tuple[int, int] | None:
    """(value, size) of the LEB128 varint at pos, None if incomplete."""
    value = shift = 0
    for i in range(pos, end):
        b = buf[i]
        value |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return value & 0xFFFFFFFF, i - pos + 1
    return None


def frame_length(buf: bytes, pos: int, end: int) -> int | None:
    """Length of the frame at pos; None if its header is incomplete, -1 if
    it cannot be a frame."""
    if end - pos < 3:
        return None
    v = varint(buf, pos, end)
    if v is None:
        return None
    value, size = v
    pad = 4 - size
    if pad < 0 or value < pad:
        return -1
    length = value - pad
    return -1 if length < size + 2 else length


def lz4_block(src: bytes, size: int) -> bytes | None:
    """Decompress one LZ4 block to exactly `size` bytes; None if it is not one."""
    if size < 0 or size > len(src) * 255:
        return None
    out = bytearray()
    i, n = 0, len(src)

    def more(length: int) -> int:
        nonlocal i
        if length == 15:
            while True:
                if i >= n:
                    return -1
                b = src[i]
                i += 1
                length += b
                if b != 255:
                    break
        return length

    while True:
        if i >= n:
            return None
        token = src[i]
        i += 1
        lit = more(token >> 4)
        if lit < 0 or len(out) + lit > size or i + lit > n:
            return None
        out += src[i:i + lit]
        i += lit
        if i == n:
            return bytes(out) if len(out) == size else None
        if i + 2 > n:
            return None
        offset = src[i] | src[i + 1] << 8
        i += 2
        if offset == 0 or offset > len(out):
            return None
        match = more(token & 15)
        if match < 0 or len(out) + match + 4 > size:
            return None
        start = len(out) - offset
        for k in range(match + 4):          # may overlap itself
            out.append(out[start + k])


class _Broken(Exception):
    pass


def _frames(buf: bytes, pos: int, end: int, at: float, out: list[Message]) -> int:
    """Read frames from buf[pos:end]; return how many were known and exact.
    Raises _Broken when the bytes are not a run of frames."""
    known = 0
    while pos < end:
        length = frame_length(buf, pos, end)
        if length is None or length < 0 or pos + length > end:
            raise _Broken
        known += _frame(buf, pos, pos + length, at, out)
        pos += length
    return known


def _frame(buf: bytes, pos: int, end: int, at: float, out: list[Message]) -> int:
    """Read one frame; 1 if it was a known message read exactly, else 0.
    Raises _Broken for a bundle that does not unpack."""
    _, size = varint(buf, pos, end)
    op = buf[pos + size] | buf[pos + size + 1] << 8
    body = pos + size + 2
    n = end - body
    if op == OP_BUNDLE:
        if n <= 4:
            raise _Broken
        raw = lz4_block(bytes(buf[body + 4:end]), struct.unpack_from("<I", buf, body)[0])
        if raw is None:
            raise _Broken
        return 1 + _frames(raw, 0, len(raw), at, out)
    if op == OP_MAP_FRAME and n == 8:
        out.append(Message(at, "frame", struct.unpack_from("<q", buf, body)[0]))
        return 1
    if op == OP_PING_RS and n == 18:
        result, sent = struct.unpack_from("<Hq", buf, body)
        if result == 0:
            out.append(Message(at, "ping", sent))
        return 1
    if op == OP_ENTER_MAP and n >= 8:
        # Only its map id is read; the rest of its body is not checked, so
        # it does not count towards recognising the stream.
        out.append(Message(at, "map", struct.unpack_from("<i", buf, body + 4)[0]))
    return 0


class StreamDecoder:
    """The server-to-client byte stream of one connection, in order, in;
    the three messages out. `recognised` says whether it is AION 2's."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.in_sync = True          # try the first byte as a frame start
        self.run = 0                 # known messages in a row since the last resync
        self.held: list[Message] = []
        self.recognised = False
        self.given_up = False
        self.seen_bytes = 0
        self.resyncs = 0             # times framing was lost after recognition

    def push(self, data: bytes, at: float) -> list[Message]:
        if self.given_up:
            return []
        self.seen_bytes += len(data)
        if not self.recognised and self.seen_bytes > GIVE_UP_BYTES:
            self.given_up = True
            self.buf.clear()
            self.held.clear()
            return []
        self.buf += data
        buf, pos, end = self.buf, 0, len(self.buf)
        out: list[Message] = []
        while pos < end:
            if not self.in_sync:
                ok = self._starts_frames(buf, pos, end)
                if not ok:
                    pos += 1
                    continue
                self.in_sync = True
            length = frame_length(buf, pos, end)
            if length is None or (length > 0 and pos + length > end and length <= MAX_FRAME):
                break                                    # wait for more bytes
            if length < 0 or length > MAX_FRAME:
                self._lose_sync()
                pos += 1
                continue
            got: list[Message] = []
            try:
                known = _frame(buf, pos, pos + length, at, got)
            except _Broken:
                self._lose_sync()
                pos += 1
                continue
            pos += length
            if self.recognised:
                out += got
                continue
            self.held += got
            self.run += known
            if self.run >= RECOGNISE_AFTER:
                self.recognised = True
                out += self.held
                self.held = []
        # Keep the unread tail; while searching for a frame start, keep at
        # most one frame's worth so a stream of noise cannot grow it.
        tail = buf[pos:]
        if not self.in_sync and len(tail) > MAX_FRAME:
            tail = tail[-MAX_FRAME:]
        self.buf = bytearray(tail)
        return out

    def gap(self) -> None:
        """Bytes are missing (a capture gap): start looking for a frame again."""
        self.buf.clear()
        self._lose_sync()

    def _lose_sync(self) -> None:
        if self.recognised and self.in_sync:
            self.resyncs += 1
        self.in_sync = False
        self.run = 0
        self.held = []

    @staticmethod
    def _starts_frames(buf: bytes, pos: int, end: int) -> bool:
        """Two known messages in a row start at pos."""
        for _ in range(2):
            length = frame_length(buf, pos, end)
            if length is None or length < 0 or length > MAX_FRAME or pos + length > end:
                return False
            try:
                if not _frame(buf, pos, pos + length, 0.0, []):
                    return False
            except _Broken:
                return False
            pos += length
        return True


DEFAULT_PORTS = frozenset({13328})   # remote ports whose streams are decoded
REQUEST_LEN = 12            # the game's ping request, one data packet (measured 2026-11-14/15)
PAIR_MAX_S = 10.0           # a reply this long after a request is not paired with it
OFFSET_SAMPLES = 15         # pairs the clock offset is the median of
OFFSET_MIN = 3              # pairs needed before any ping is reported
SEED_AGREE_MS = 5.0         # a new connection's first pair must agree with the seed this well
MAX_PENDING_SEGMENTS = 200  # out-of-order segments held before giving the gap up
SEQ_MOD = 1 << 32


@dataclass
class GameConnection:
    """One AION 2 connection's packets in (both directions), its game pings
    and map entries out."""
    decoder: StreamDecoder = field(default_factory=StreamDecoder)
    next_seq: int | None = None
    pending: dict = field(default_factory=dict)        # seq -> payload, out of order
    requests: deque = field(default_factory=lambda: deque(maxlen=4))   # [time, paired]
    offsets: deque = field(default_factory=lambda: deque(maxlen=OFFSET_SAMPLES))
    unresolved: list = field(default_factory=list)     # (arrival, sent) before calibration
    pings: list = field(default_factory=list)          # (arrival, ms), not yet taken
    maps: list = field(default_factory=list)           # (arrival, map id), not yet taken
    gaps: int = 0                                      # capture gaps given up on
    seed: list | None = None                           # offsets carried over, until a pair confirms them

    def add(self, time: float, from_remote: bool, length: int, seq: int | None,
            payload: bytes | None) -> None:
        if not from_remote:
            if length == REQUEST_LEN:
                self.requests.append([time, False])
            return
        if not length or payload is None or seq is None:
            return
        if self.next_seq is None:
            self.next_seq = seq
        if (seq + length - self.next_seq) % SEQ_MOD > SEQ_MOD // 2 or seq + length == self.next_seq:
            return                                     # already delivered (a retransmission)
        self.pending[seq] = payload
        while True:
            hit = next((q for q, b in self.pending.items()
                        if (self.next_seq - q) % SEQ_MOD < len(b)), None)
            if hit is None:
                break
            b = self.pending.pop(hit)
            part = b[(self.next_seq - hit) % SEQ_MOD:]
            self.next_seq = (self.next_seq + len(part)) % SEQ_MOD
            for m in self.decoder.push(part, time):
                self._message(m)
        if len(self.pending) > MAX_PENDING_SEGMENTS:
            self.pending.clear()
            self.decoder.gap()
            self.next_seq = None
            self.gaps += 1

    def _message(self, m: Message) -> None:
        if m.kind == "map":
            self.maps.append((m.at, m.value))
            return
        if m.kind != "ping":
            return
        req = next((r for r in reversed(self.requests) if r[0] < m.at), None)
        if req is not None and not req[1] and m.at - req[0] <= PAIR_MAX_S:
            req[1] = True
            sample = req[0] * 1000 - m.value
            if self.seed:
                if abs(sample - statistics.median(self.seed)) <= SEED_AGREE_MS:
                    self.offsets.extend(self.seed)
                self.seed = None
            self.offsets.append(sample)
        self.unresolved.append((m.at, m.value))
        if len(self.offsets) >= OFFSET_MIN:
            offset = statistics.median(self.offsets)
            for at, sent in self.unresolved:
                self.pings.append((at, round(at * 1000 - (sent + offset), 1)))
            self.unresolved = []

    def take(self) -> tuple[list, list]:
        """(pings, map entries) since the last call."""
        pings, maps = self.pings, self.maps
        self.pings, self.maps = [], []
        return pings, maps
