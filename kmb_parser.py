#!/usr/bin/env python3
"""
Parse Kongsberg KM Binary (#KMB) datagrams from a binary file.

Supports:
  - one or more concatenated datagrams
  - JSON, JSON Lines, or CSV output
  - strict validation or recovery by scanning for the next #KMB marker

The documented version-1 datagram is little-endian and 132 bytes long.
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Iterator, TextIO

MESSAGE = b"#KMB"
VERSION_1_SIZE = 132

# Little-endian layout:
# 4s magic
# H datagram_length
# H version
# I UTC seconds
# I UTC nanoseconds
# I status
# d latitude
# d longitude
# 21f remaining float fields
FORMAT_V1 = struct.Struct("<4sHHIIIdd21f")


@dataclass(frozen=True)
class KmbMessage:
    offset: int
    datagram_length: int
    version: int
    utc_seconds: int
    utc_nanoseconds: int
    timestamp_utc: str
    status: int
    status_flags: list[str]
    latitude_deg: float
    longitude_deg: float
    ellipsoid_height_m: float
    roll_deg: float
    pitch_deg: float
    heading_deg: float
    heave_m: float
    roll_rate_deg_s: float
    pitch_rate_deg_s: float
    yaw_rate_deg_s: float
    north_velocity_m_s: float
    east_velocity_m_s: float
    down_velocity_m_s: float
    latitude_error_m: float
    longitude_error_m: float
    height_error_m: float
    roll_error_deg: float
    pitch_error_deg: float
    heading_error_deg: float
    heave_error_m: float
    north_acceleration_m_s2: float
    east_acceleration_m_s2: float
    down_acceleration_m_s2: float
    delayed_heave_utc_seconds: int
    delayed_heave_utc_nanoseconds: int
    delayed_heave_timestamp_utc: str
    delayed_heave_m: float


STATUS_BITS = {
    0: "invalid_horizontal_position_velocity",
    1: "invalid_roll_pitch",
    3: "invalid_heave_vertical_velocity",
    4: "invalid_acceleration",
    5: "invalid_delayed_heave",
    16: "reduced_horizontal_position_velocity",
    17: "reduced_roll_pitch",
    19: "reduced_heave_vertical_velocity",
    20: "reduced_acceleration",
    21: "reduced_delayed_heave",
}


class KmbParseError(ValueError):
    pass


def iso_timestamp(seconds: int, nanoseconds: int) -> str:
    if not 0 <= nanoseconds < 1_000_000_000:
        raise KmbParseError(f"invalid nanoseconds value: {nanoseconds}")
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
    base = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{nanoseconds:09d}Z"


def decode_status(status: int) -> list[str]:
    return [name for bit, name in STATUS_BITS.items() if status & (1 << bit)]


def parse_v1(data: bytes, offset: int) -> KmbMessage:
    if len(data) < VERSION_1_SIZE:
        raise KmbParseError(
            f"truncated datagram at byte {offset}: "
            f"need {VERSION_1_SIZE} bytes, got {len(data)}"
        )

    unpacked = FORMAT_V1.unpack_from(data)
    (
        magic,
        datagram_length,
        version,
        utc_seconds,
        utc_nanoseconds,
        status,
        latitude,
        longitude,
        *floats,
    ) = unpacked

    if magic != MESSAGE:
        raise KmbParseError(f"bad marker at byte {offset}: {magic!r}")
    if version != 1:
        raise KmbParseError(f"unsupported KMB version {version} at byte {offset}")
    if datagram_length < VERSION_1_SIZE:
        raise KmbParseError(
            f"invalid datagram length {datagram_length} at byte {offset}"
        )
    if len(floats) != 21:
        raise AssertionError("internal format mismatch")

    (
        ellipsoid_height,
        roll,
        pitch,
        heading,
        heave,
        roll_rate,
        pitch_rate,
        yaw_rate,
        north_velocity,
        east_velocity,
        down_velocity,
        latitude_error,
        longitude_error,
        height_error,
        roll_error,
        pitch_error,
        heading_error,
        heave_error,
        north_acceleration,
        east_acceleration,
        down_acceleration,
    ) = floats

    delayed_seconds, delayed_nanoseconds, delayed_heave = struct.unpack_from(
        "<IIf", data, 120
    )

    return KmbMessage(
        offset=offset,
        datagram_length=datagram_length,
        version=version,
        utc_seconds=utc_seconds,
        utc_nanoseconds=utc_nanoseconds,
        timestamp_utc=iso_timestamp(utc_seconds, utc_nanoseconds),
        status=status,
        status_flags=decode_status(status),
        latitude_deg=latitude,
        longitude_deg=longitude,
        ellipsoid_height_m=ellipsoid_height,
        roll_deg=roll,
        pitch_deg=pitch,
        heading_deg=heading,
        heave_m=heave,
        roll_rate_deg_s=roll_rate,
        pitch_rate_deg_s=pitch_rate,
        yaw_rate_deg_s=yaw_rate,
        north_velocity_m_s=north_velocity,
        east_velocity_m_s=east_velocity,
        down_velocity_m_s=down_velocity,
        latitude_error_m=latitude_error,
        longitude_error_m=longitude_error,
        height_error_m=height_error,
        roll_error_deg=roll_error,
        pitch_error_deg=pitch_error,
        heading_error_deg=heading_error,
        heave_error_m=heave_error,
        north_acceleration_m_s2=north_acceleration,
        east_acceleration_m_s2=east_acceleration,
        down_acceleration_m_s2=down_acceleration,
        delayed_heave_utc_seconds=delayed_seconds,
        delayed_heave_utc_nanoseconds=delayed_nanoseconds,
        delayed_heave_timestamp_utc=iso_timestamp(
            delayed_seconds, delayed_nanoseconds
        ),
        delayed_heave_m=delayed_heave,
    )


def iter_kmb_messages(
    stream: BinaryIO, *, recover: bool = False
) -> Iterator[KmbMessage]:
    blob = stream.read()
    offset = 0

    while offset < len(blob):

        found = blob.find(MESSAGE, offset + 1)
               
        if found < 0:
            return
        
        offset = found

        if len(blob) - offset < 8:
            raise KmbParseError(f"truncated KMB header at byte {offset}")

        datagram_length, version = struct.unpack_from("<HH", blob, offset + 4)

        if datagram_length < 8:
            raise KmbParseError(
                f"invalid datagram length {datagram_length} at byte {offset}"
            )
        if offset + datagram_length > len(blob):
            raise KmbParseError(
                f"truncated datagram at byte {offset}: declared "
                f"{datagram_length} bytes, only {len(blob) - offset} remain"
            )

        datagram = blob[offset : offset + datagram_length]

        if version == 1:
            yield parse_v1(datagram, offset)
        else:
            raise KmbParseError(
                f"unsupported KMB version {version} at byte {offset}"
            )

        offset += datagram_length


def message_dict(message: KmbMessage) -> dict:
    row = asdict(message)
    row["status_flags"] = ",".join(message.status_flags)
    return row


def write_json(messages: list[KmbMessage], output: TextIO) -> None:
    json.dump([asdict(m) for m in messages], output, indent=2)
    output.write("\n")


def write_jsonl(messages: list[KmbMessage], output: TextIO) -> None:
    for message in messages:
        output.write(json.dumps(asdict(message), separators=(",", ":")) + "\n")


def write_csv(messages: list[KmbMessage], output: TextIO) -> None:
    if not messages:
        return
    rows = [message_dict(m) for m in messages]
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse Kongsberg KM Binary (#KMB) datagrams."
    )
    parser.add_argument("input", type=Path, help="binary file containing KMB data")
    parser.add_argument(
        "-o", "--output", type=Path, help="output file; defaults to stdout"
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("json", "jsonl", "csv"),
        default="jsonl",
        help="output format (default: jsonl)",
    )
    parser.add_argument(
        "--recover",
        action="store_true",
        help="scan forward to the next #KMB marker after unrelated bytes",
    )
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    try:
        with args.input.open("rb") as source:
            messages = list(iter_kmb_messages(source, recover=args.recover))

        destination: TextIO
        close_destination = False
        if args.output:
            destination = args.output.open("w", encoding="utf-8", newline="")
            close_destination = True
        else:
            destination = sys.stdout

        try:
            if args.format == "json":
                write_json(messages, destination)
            elif args.format == "jsonl":
                write_jsonl(messages, destination)
            else:
                write_csv(messages, destination)
        finally:
            if close_destination:
                destination.close()

        print(
            f"Parsed {len(messages)} KMB message(s).",
            file=sys.stderr,
        )
        return 0

    except (OSError, KmbParseError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())