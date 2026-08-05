#!/bin/sh

[ $# -eq 1 ] || { cat << EOUSE ; exit 1 ; }
  Usage: $0 [major | minor | patch]

Release mailin-embedded.
EOUSE

cargo release --execute --features 'rtls' --tag-prefix mailin-embedded- $1
