#!/bin/bash

ip link add test0 type veth peer name test1
ip netns add test
ip link set test0 netns test
ip addr add 10.0.0.1 dev test1

ip link set test1 up
ip netns exec test ip link set test0 up
