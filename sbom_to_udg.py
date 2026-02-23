import json
import argparse
from datetime import datetime

def convert(input_file, output_file):
    print("Parsing SBOM...")
    with open(input_file, 'r') as f:
        data = json.load(f)
    print(f"Done: {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args()
    convert(args.input, args.output)
