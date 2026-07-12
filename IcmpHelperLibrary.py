# #################################################################################################################### #
# Program Name: IcmpHelperLibrary.py                                                                                   #
# Author: Christopher Vote                                                                                             #
#                                                                                                                      #
# Description:                                                                                                         #
# This module provides helper classes and functions for constructing, sending, and processing ICMP packets.            #
# It implements the core functionality required for network diagnostic tools such as ping utilities, including         #
# packet creation, checksum calculation, transmission, and response handling.                                          #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #


# #################################################################################################################### #
# Imports                                                                                                              #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select
import statistics               # For mean


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
# Description:                                                                                                         #
# Provides a collection of ICMP networking helper methods for creating packets, sending echo requests, and processing  #
# replies from remote hosts.                                                                                           #
#                                                                                                                      #
########################################################################################################################

class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 5
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #

        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("<d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")
            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        """ Code citation: I referred to the code in the file traceroute.c in traceroute.tar.Z from 
        ftp.ee.lbl.gov while studying this method; in particular the function packet_ok(). I also referred
        to the description of tracerout routine at RFC 1739. 
        """

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.

            # Check that the sequence number, packet identifier and raw data are valid
            #   check getDataRaw() against getIcmpData, etc.
            # Hint: Work through comparing each value and identify if this is a valid response.

            # process data for echo response only
            if icmpReplyPacket.getIcmpType() == 0:
                validData = self.getDataRaw() == icmpReplyPacket.getIcmpData()
            else:
                validData = True

            icmpReplyPacket.setIcmpData_isValid(validData)

            validSequence = self.getPacketSequenceNumber() == icmpReplyPacket.getIcmpSequenceNumber()
            icmpReplyPacket.setIcmpSequenceNumber_isValid(validSequence)

            validIdentifier = self.getPacketIdentifier() == icmpReplyPacket.getIcmpIdentifier()
            icmpReplyPacket.setIcmpIdentifier_isValid(validIdentifier)

            packetValidationBool = (icmpReplyPacket.getIcmpData_isValid()
                                    and icmpReplyPacket.getIcmpSequenceNumber_isValid()
                                    and icmpReplyPacket.getIcmpIdentifier_isValid())


            # Set isvalid variable for each based on comparison result
            icmpReplyPacket.setIsValidResponse(packetValidationBool)


        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeSent = time.time()

                # Set timeLeft to global self.__ipTimeout global variable
                timeLeft = self.__ipTimeout
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)

                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")

                while True:
                    recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                    timeReceived = time.time()
                    icmpType, icmpCode = recvPacket[20:22]

                    if icmpType == 0:
                        recvIdentifier = struct.unpack("!H", recvPacket[24:26])[0]
                    else:
                        ihl = (recvPacket[28] & 0x0F) * 4
                        recvIdentifier = struct.unpack("!H", recvPacket[28 + ihl + 4:28 + ihl + 6])[0]

                    rtt = (timeReceived - timeSent) * 1000

                    # Adjust offset for ICMP type
                    if icmpType == 11:                      # Time exceeded
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket, originalPacket=self)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), rtt, icmpType, icmpCode, addr[0])
                        return icmpType

                    elif icmpType == 0:                     # Echo reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket, originalPacket=self)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), rtt, icmpType, icmpCode, addr[0])
                        return rtt

                    elif icmpType == 3:                     # Destination unreachable
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket, originalPacket=self)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        icmpReplyPacket.printResultToConsole(self.getTtl(), rtt, icmpType, icmpCode, addr[0])
                        return icmpType

                    else:
                        print("error")

            except timeout:
                pass

            finally:
                mySocket.close()

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # Create variable for valid identifier
        __icmpData_isValid = False
        __icmpSequenceNumber_isValid = False
        __icmpIdentifier_isValid = False

        """
        Code citation: Trace data which populates these messages copied from:
        Internet Control Message Protocol (ICMP) Parameters
        https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes-3
        """

        __typeAndCodeMap = {               # { type : { code : `trace statement` } }
            0 : {0 : "0 (Echo Reply)"},
            3 : {0 : "0 (Net Unreachable)",
                 1 : "1 (Host Unreachable)",
                 2 : "2 (Protocol Unreachable)",
                 3 : "3 (Port Unreachable)",
                 4 : "4 (Fragmentation Needed and Don't Fragment was Set)",
                 5 : "5 (Source Route Failed)",
                 6 : "6 (Destination Network Unknown)",
                 7 : "7 (Destination Host Unknown)",
                 8 : "8 (Source Host Isolated)",
                 9 : "9 (Communication with Destination Network is Administratively Prohibited)",
                 10 : "10 (Communication with Destination Host is Administratively Prohibited)",
                 11 : "11 (Destination Network Unreachable for Type of Service)",
                 12 : "12 (Destination Network Unreachable for Type of Service)",
                 13 : "13 (Communication Administratively Prohibited)",
                 14 : "14 (Host Precedence Violation)",
                 15 : "15 (Precedence cutoff in effect)"},
            11 : {0 : "0 (Time to Live exceeded in Transit)",
                  1 : "1 (Fragment Reassembly Time Exceeded"
            }
        }

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket, originalPacket):
            self.__recvPacket = recvPacket
            self.__originalPacket = originalPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        # _isValid getters
        # create getter and setter for icmpIdentifier_isValid and seq number, data
        def getIcmpData_isValid(self):
            return self.__icmpData_isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.__icmpSequenceNumber_isValid

        def getIcmpIdentifier_isValid(self):
            return self.__icmpIdentifier_isValid

        def isValidResponse(self):
            return self.__isValidResponse

        # _isValid setters
        def setIcmpData_isValid(self, booleanValue):
            self.__icmpData_isValid = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.__icmpSequenceNumber_isValid = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__icmpIdentifier_isValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #

        """
        Code citation: For the output format, I gained important insights from running the ping command in Linux.
        For guidance, I referred to the Linux man page for ping(8) at https://linux.die.net/man/8/ping.
        """

        def printResultToConsole(self, ttl, rtt, icmpType, icmpCode, addr):

            # Check and report errors only for echo response
            if self.getIcmpType() == 0:
                if not self.isValidResponse():
                    if not self.getIcmpData_isValid():
                        print("Expected raw data value %s, actual value %s" %
                              (self.__originalPacket.getDataRaw(), self.getIcmpData()))
                    if not self.getIcmpSequenceNumber_isValid():
                        print("Expected sequence number data %d, actual value %d" %
                              (self.__originalPacket.getPacketSequenceNumber(), self.getIcmpSequenceNumber()))
                    if not self.getIcmpIdentifier_isValid():
                        (print("Expected identifier value %d, actual value %d" %
                         (self.__originalPacket.getPacketIdentifier(), self.getIcmpIdentifier())))
                        return 0
            else:
                self.setIcmpData_isValid(True)
                self.setIcmpSequenceNumber_isValid(True)
                self.setIcmpIdentifier_isValid(True)
                self.setIsValidResponse(True)

            code = self.__typeAndCodeMap[icmpType][icmpCode]
            print("TTL=%d     RTT=%.0f ms     Type=%d    Code=%s   %s" %
                  (ttl, rtt, icmpType, code, addr))


    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        pingCount = 4
        # Save rtt responses in order to calculate statistics
        rttBuffer = []

        # Message to start ping
        print("Pinging %s" % host)


        for i in range(pingCount):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit
            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            rtt = icmpPacket.sendEchoRequest()                                                # Build IP
            # rtt is the rtt value for the current packet or 0
            if rtt:
                rttBuffer.append(rtt)

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        # calculate the packet loss rate (in percentage).
        time = sum(rttBuffer)
        successfulPings = len(rttBuffer)
        droppedPings = pingCount - successfulPings

        if successfulPings == 0:
            percentageLoss = 100.0
        else:
            percentageLoss = 100 * (droppedPings / pingCount)

        # Determine rtt minimum, maximum, and average
        rttMin = min(rttBuffer)
        rttMax = max(rttBuffer)
        rttMean = statistics.mean(rttBuffer)


        # Print transmission results
        print("%d packets transmitted, %d received, %s lost, %.0f%% packet loss, time %.0f ms" %
              (pingCount, successfulPings, droppedPings, percentageLoss, time))

        # Print rtt min/max/ave stats
        print("rtt min/avg/max = %.0f/%.0f/%.0f ms" % (rttMin, rttMean, rttMax))

    """ 
    Code citation: When composing __sendIcmpTraceRoute(), I referred to the implementation 
    in the file traceroute.c in traceroute.tar.Z from ftp.ee.lbl.gov 
    """

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        print("Traceroute to (%s) %s" % (host, host))

        # Loop while code 11 time exceeded replies are received and code 3 destination unreachable are not
        isEnd = False       # Flag for destination reached indicated by type 3
        ttl = 1               # For incrementing TTL
        i = 0                   # For sequence number
        maxTtl = 30

        while not isEnd and ttl <= maxTtl:
             # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

             # Set TTL
            icmpPacket.setTtl(ttl)

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number. Limit based on ICMP header standards
            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)

            # Get icmpType as return value in order to detect end
            icmpType = icmpPacket.sendEchoRequest()                                     # Build IP

            # toggle isEnd if the icmpType is 3 or 0 (type zero returns RTT in sendEchoRequst() which is a float)
            if icmpType == 3 or icmpType == 0 or isinstance(icmpType, float):
                isEnd = True

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0

            ttl += 1
            i += 1



    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    # icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    # icmpHelperPing.traceRoute("122.56.99.243")
    # icmpHelperPing.traceRoute("google.com")
    icmpHelperPing.traceRoute("8.8.8.8")

    # unreachable maybe
    # icmpHelperPing.traceRoute("210.152.243.234")                    # Samina
    # icmpHelperPing.traceRoute("122.56.99.243")                      # Samina
    # icmpHelperPing.traceRoute("200.10.227.250")                     # assignment example        / worked
    # icmpHelperPing.traceRoute("169.254.0.3")                        # Ed discussion

    # google
    # icmpHelperPing.traceRoute("www.google.com")
    # icmpHelperPing.traceRoute("142.251.32.110")
    # icmpHelperPing.traceRoute("172.217.164.174")
    # icmpHelperPing.traceRoute("66.249.77.224")

    # icmpHelperPing.traceRoute("128.119.245.12")                         # gaia.cs.umass.edu
    # icmpHelperPing.traceRoute("172.67.144.43")                          # www.msuiit.edu.ph
    # icmpHelperPing.traceRoute("172.67.204.195")                         # www.cu.edu.ph
    # icmpHelperPing.traceRoute("153.127.164.138")                        # www.hit-u.ac.jp




    # icmpHelperPing.traceRoute("209.233.126.254")


if __name__ == "__main__":
    main()
