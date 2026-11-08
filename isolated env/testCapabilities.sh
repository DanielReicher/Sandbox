
#!/bin/sh

echo "Checking process capabilities..."

echo "Current process:"
id

echo "Current capabilities:"
grep '^Cap' /proc/self/status

echo "Decoded capabilities:"
capsh --decode=$(grep '^CapEff:' /proc/self/status | awk '{print $2}')
