KMB message parser

This command-line program parses Kongsberg KM Binary datagrams beginning withthe four-byte marker #KMB.

Usage

python3 kmb_parser.py input.bin
python3 kmb_parser.py input.bin --format json -o messages.json
python3 kmb_parser.py input.bin --format csv -o messages.csv
python3 kmb_parser.py noisy_capture.bin --recover

The parser supports version 1 datagrams and validates their declared length,version, timestamps, and truncation.