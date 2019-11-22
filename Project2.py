from socket import *
import os
import sys
import struct
import time
import select
import binascii
import socket


ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 1

# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
# In this function we make the checksum of our packet
# hint: see icmpPing lab
    string = bytearray(string)
    checksum = 0
    maxcount = (len(string) // 2) * 2

    for count in range(0, maxcount, 2):
        val = string[count+1] * 256 + string[count]
        checksum += val
        checksum = checksum & 0xffffffff

    if maxcount < len(string):
        checksum += string[-1]
        checksum = checksum & 0xffffffff

    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum = checksum + (checksum >> 16)
    final = ~checksum
    final = final & 0xffff
    final = final >> 8 | (final << 8 & 0xff00)
    return final

def build_packet():
# In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
# packet to be sent was made, secondly the checksum was appended to the header and
# then finally the complete packet was sent to the destination.
# Make the header in a similar way to the ping exercise.
    checks = 0
    ID = os.getpid() & 0xFFFF
# Append checksum to the header.
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checks, ID, 1)
    data = struct.pack("d", time.time())
# So the function ending should look like this
    checks= checksum(header + data)
    checks = htons(checks)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checks, ID, 1)
    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    for ttl in range(1,MAX_HOPS):
        for tries in range(TRIES):
            destAddr = socket.gethostbyname(hostname)

            #Fill in start
            # Make a raw socket named mySocket
            ICMP = socket.getprotobyname('icmp')
            mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP)
            mySocket.bind(('', 5678))
            #Fill in end
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t= time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []: # Timeout
                    print(" * * * Request timed out.")

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    print(" * * * Request timed out.")

            except socket.timeout:
                continue

            else:
                #Fill in start
                #Fetch the icmp type from the IP packet
                icmpHead = recvPacket[20:28]
                types, code, checks, packetID, sequence = struct.unpack("bbHHh", icmpHead)
                #Fill in end
                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print(" %d rtt=%.0f ms %s -- %s" %(ttl,(timeReceived -t)*1000, addr[0], socket.getfqdn(addr[0])))
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print(" %d rtt=%.0f ms %s -- %s" %(ttl,(timeReceived -t)*1000, addr[0], socket.getfqdn(addr[0])))
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    print(" %d rtt=%.0f ms %s -- %s" %(ttl,(timeReceived -t)*1000, addr[0], socket.getfqdn(addr[0])))
                    return
                else:
                    print("error")
                    break
            finally:
                mySocket.close()
print('****************************************************')
print('                  hulu.com')
print('****************************************************')
get_route("hulu.com")

print('****************************************************')
print('                  blackboard.com')
print('****************************************************')
get_route("blackboard.com")

print('****************************************************')
print('                  twitch.tv')
print('****************************************************')
get_route("twitch.tv")

print('****************************************************')
print('                  mybama.com')
print('****************************************************')
get_route("mybama.com")
