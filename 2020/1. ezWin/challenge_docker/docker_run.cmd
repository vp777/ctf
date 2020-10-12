:when running with process isolation, make sure the host firewall rules allow our inbound connections
docker run --rm --isolation=hyperv -it -p 4444:4444 --name ezwin1909 ctf/ezwin:1909