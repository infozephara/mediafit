#!/bin/sh
set -e
D="$HOME/.mediafit"; mkdir -p "$D"
cp mediafit.py "$D/mediafit.py"; chmod +x "$D/mediafit.py"
echo "installed: $D/mediafit.py"