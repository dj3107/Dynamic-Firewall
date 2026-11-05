#!/bin/bash
# Runs all automated tests (no Mininet needed). Stop the demo's Ryu controller first:
# the end-to-end test starts its own controller on ports 8080 / 6653.
cd "$(dirname "$0")/.."
export PATH=$PATH:$HOME/.local/bin
if (echo > /dev/tcp/127.0.0.1/8080) 2>/dev/null; then
  echo "Port 8080 is in use - stop the running ryu-manager first."; exit 1
fi
set -e
python3 tests/test_controller_logic.py
python3 tests/test_policy_server.py
python3 tests/test_experiment_parsing.py
python3 tests/local_test.py
echo "ALL TESTS PASSED"
