#!/bin/bash
tmux &
# Session Name
session="Socket Test Env"

tmux new-session -d -s $session
tmux rename-window -t 0 'test env'
tmux split-window -v
tmux split-window -h

tmux send-keys -t 'test env'.1 'nc -lU /var/tmp/dsocket' C-m

tmux send-keys -t 'test env'.2 'nc -U /var/tmp/dsocket' C-m

tmux attach-session -t $session:0

