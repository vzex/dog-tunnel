#!/bin/bash
nohup ./dtunnel_s -ssl -admin :8009 -dbuser dog -dbpass dog -cert keys/server.crt -key keys/server.key  -https -addr :8008 > log.txt 2>&1 &
