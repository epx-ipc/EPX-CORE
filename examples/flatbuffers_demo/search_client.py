#!/usr/bin/env python3
"""FlatBuffers-over-EPX demo, client side — Python talking to the C++
search_host through the same .fbs schema (see docs/SERIALIZATION.md).

Usage: python3 search_client.py "query" [limit]
Needs: pip install flatbuffers, plus the EPX-PYTHON binding as a sibling
checkout (or installed).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))          # epxdemo/ (generated)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "EPX-PYTHON", "src"))

import flatbuffers  # noqa: E402
import epx  # noqa: E402
from epxdemo.SearchRequest import SearchRequestT  # noqa: E402
from epxdemo.SearchResponse import SearchResponse  # noqa: E402


def main():
    query = sys.argv[1] if len(sys.argv) > 1 else "protocol"
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    # Build the FlatBuffers request (object API for brevity).
    req = SearchRequestT()
    req.query = query
    req.limit = limit
    builder = flatbuffers.Builder(64)
    builder.Finish(req.Pack(builder))

    ident = epx.Identity.load_or_create("com.epx.demo.fbsearch.client")
    client = epx.Client(ident)
    raw = client.get("com.epx.demo.fbsearch", "search", bytes(builder.Output()))

    resp = SearchResponse.GetRootAs(raw, 0)
    print(f'{resp.ResultsLength()} result(s) for "{query}":')
    for i in range(resp.ResultsLength()):
        result = resp.Results(i)
        print(f"  {result.Score():.2f}  {result.Title().decode()}")


if __name__ == "__main__":
    main()
