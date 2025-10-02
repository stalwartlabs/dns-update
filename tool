#!/bin/sh

# convenience tool for automating various routines

if ! command -v cargo >/dev/null 2>&1
then
  if [ -x ~/.cargo/env ]
  then
    . ~/.cargo/env
  else
    cat <<'EOL' >&2
[FATAL] cargo is not installed or could not be found on this system!

Hint: Linux and MacOS users can install Cargo via the following:

  $ wget -O- https://sh.rustup.rs | sh -s

EOL
    exit
  fi
fi

man() {
  [ "$1" = "--help" ] || [ "$1" = "-h" ]
  ST=$?
  cat <<'HELP' >&$((ST + 1))
Usage: ./tool [ARGS...]
  -v, --verbose  verbose output mode
  -q, --quiet    quiet output mode
  -h, --help     print this help message
Tools:
  dev            short for test fmt clippy
  full           real Linode integration tests
  test           does cargo test
  fmt            does cargo fmt
  clippy         does cargo clippy
  bot            clippy warnings -> errors

E.x. to test and fmt: ./tool test fmt

If you don't know what to do, just:

  ./tool dev

HELP
  exit $((1 - ST))
}

tool() {
  case "$2" in
    dev)
      DEF=""
      "$1" cargo test
      "$1" cargo fmt
      "$1" cargo clippy --all-targets
      ;;
    full)
      DEF=""
      "$1" cargo test
      "$1" cargo fmt
      "$1" cargo clippy --all-targets
       printf "\033[0;31mNOTICE:\033[0m Running live integration test posting records to ci-cd.stalwart.dns-update.jaygiffin.com. It usually takes 10-15 seconds but can take up to 2 minutes for the records to show up and the timeout is 3 minutes. Be patient; the test is not broken and it will give you a beautiful error log if it fails after 3 minutes.\n"
      "$1" cargo test linode_integration_test -- --include-ignored
      ;;
    test)
      DEF=""
      "$1" cargo test
      ;;
    fmt)
      DEF=""
      "$1" cargo fmt
      ;;
    clippy)
      DEF=""
      "$1" cargo clippy --all-targets
      ;;
    bot)
      DEF=""
      RUSTFLAGS="$RUSTFLAGS -A dead_code" "$1" cargo test
      "$1" cargo fmt
      "$1" cargo clippy --all-targets -- -D warnings -A dead_code
      ;;
    -*)
      if [ "$2" = -h ] || [ "$2" = --help ]
      then
        man "$2"
      elif [ "$1" = ":" ]
      then
        APP="$APP $2"
      fi
      ;;
    *)
      man "$2"
      ;;
  esac
}

log() (
  set -x
  exec "$@" $APP
)

DEF="-h"
APP=""
for arg in "$@"
do
  # check arguments:
  tool : "$arg"
done
set -e
export RUST_BACKTRACE=1
for arg in $DEF "$@"
do
  # execute in order:
  tool log "$arg"
done
