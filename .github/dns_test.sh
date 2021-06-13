#!/usr/bin/env sh

dns_test_add() {
  fulldomain=$1
  txtvalue=$2
  _info "adding dns record: ${fulldomain}: ${txtvalue}"
  echo "txt-record=${fulldomain},\"${txtvalue}\"" >> /dnsmasq.conf
  killall -9 dnsmasq
  _sleep 1
  dnsmasq -C /dnsmasq.conf
}

#Usage: fulldomain txtvalue
#Remove the txt record after validation.
dns_test_rm() {
  fulldomain=$1
  txtvalue=$2
  _info "removing dns record"
  _debug fulldomain "$fulldomain"
  _debug txtvalue "$txtvalue"
#  grep -v "txt-record=${fulldomain},\"${txtvalue}\"" /dnsmasq.conf > /dnsmasq.conf
#  killall -9 dnsmasq
#  dnsmasq -C /dnsmasq.conf
}
