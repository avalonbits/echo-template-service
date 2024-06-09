#!/bin/bash
export $(cat .env | grep -v ^\# | xargs) > /dev/null && ./tmp/main
