"""
Program Name: icmp_ping_backend.py

Author: Christopher Vote
Email: cbourjaily@gmail.com

This module provides helper classes and functions for constructing, sending, and processing ICMP packets.
It implements the core functionality required for network diagnostic tools such as ping utilities, including
packet creation, checksum calculation, transmission, and response handling.
"""

from __future__ import annotations
import os
from socket import *
import struct
import time
import select
import statistics

# For GUI integration
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class PingReply:
    """
    Represents the result of a single ICMP echo request. Stores timing, protocol, and validation
    information.
    """
    sequence_number: int
    success: bool                                 # True if a valid reply was received
    rtt_ms: Optional[float] = None           # None if timed out
    ttl: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[str] = None
    address: Optional[str] = None
    is_valid: bool = True                         # sequence/id/data all matched
    error_message: Optional[str] = None


@dataclass
class PingSummary:
    """
    Represents the complete results of a ping operation, including overall transmission statistics
    and summary statistics for the collection of individual echo request results.
    """

    host: str
    target_ip: Optional[str] = None
    packets_transmitted: int = 0
    packets_received: int = 0
    packets_lost: int = 0
    percent_loss: float = 0.0
    rtt_min: Optional[float] = None
    rtt_avg: Optional[float] = None
    rtt_max: Optional[float] = None
    replies: List[PingReply] = field(default_factory=list)
    error: Optional[str] = None


class IcmpHelperLibrary:
    """
    Provides a collection of ICMP networking helper methods for creating packets,
    sending echo requests, and processing replies from remote host.
    """


    class IcmpPacket:
        """
        Represents an ICMP packet and provides methods for constructing, sending,
        and validating ICMP Echo Request and Echo Reply messages.

        References:
            https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
        """

        # IcmpPacket Class Scope Variables
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __data_raw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packet_identifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packet_sequence_number = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 5
        __ttl = 255                     # Time to live
        __DEBUG_IcmpPacket = False      # Allows for debug output


        """Getter methods."""

        def get_icmp_target(self):
            return self.__icmpTarget

        def get_data_raw(self):
            return self.__data_raw

        def get_icmp_type(self):
            return self.__icmpType

        def get_icmp_code(self):
            return self.__icmpCode

        def get_packet_checksum(self):
            return self.__packetChecksum

        def get_packet_identifier(self):
            return self.__packet_identifier

        def get_packet_sequence_number(self):
            return self.__packet_sequence_number

        def get_ttl(self):
            return self.__ttl


        """Setter methods."""

        def set_icmp_target(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def set_icmp_type(self, icmpType):
            self.__icmpType = icmpType

        def set_icmp_code(self, icmpCode):
            self.__icmpCode = icmpCode

        def set_packet_checksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def set_packet_identifier(self, packet_identifier):
            self.__packet_identifier = packet_identifier

        def set_packet_sequence_number(self, sequenceNumber):
            self.__packet_sequence_number = sequenceNumber

        def set_ttl(self, ttl):
            self.__ttl = ttl


        """Private helper methods."""

        def __recalculate_checksum(self):
            """
            Compute and update the ICMP checksum for the current packet.

            Calculates the Internet checksum over the packet header and payload
            using the one's complement checksum algorithm defined for ICMP.
            """

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
            answer = ~checksum                                  # Invert bits
            answer = answer & 0xffff                            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.set_packet_checksum(answer)


        def __pack_header(self):
            """
            Pack the ICMP header fields into their binary representation.
            """

            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.get_icmp_type(),               #  8 bits / 1 byte  / Format code B
                                   self.get_icmp_code(),                  #  8 bits / 1 byte  / Format code B
                                   self.get_packet_checksum(),            # 16 bits / 2 bytes / Format code H
                                   self.get_packet_identifier(),          # 16 bits / 2 bytes / Format code H
                                   self.get_packet_sequence_number()      # 16 bits / 2 bytes / Format code H
                                   )


        def __encode_data(self):
            """
            Construct the ICMP payload.

            Encodes the user data as UTF-8 and prefixes it with an 8-byte
            timestamp used to calculate round-trip time.
            """

            data_time = struct.pack("<d", time.time())           # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.get_data_raw().encode("utf-8")
            self.__data = data_time + dataRawEncoded

        def __pack_and_recalculate_checksum(self):
            """
            Assemble the packet and update its checksum.

            The header is initially packed with a placeholder checksum, the
            checksum is computed over the complete packet, and the header is
            rebuilt to include the calculated checksum.
            """

            self.__pack_header()
            self.__encode_data()
            self.__recalculate_checksum()
            self.__pack_header()                 # Repack with computed checksum.

        # Implementation informed by:
        # - packet_ok() in traceroute.c (ftp.ee.lbl.gov/traceroute.tar.Z)
        # - RFC 1739 description of traceroute

        def __validate_icmp_reply_packet_with_original_ping_data(self, icmp_reply_packet: IcmpPacket_EchoReply) -> None:

            """
            Validate an ICMP reply against the original echo request.

            Verifies that the identifier, sequence number, and payload in the
            reply match those of the original request and records the validation
            results in the reply packet.

            :param icmp_reply_packet: he parsed ICMP reply to validate against this 
            request's original data.
            """

            # process data for echo response only
            if icmp_reply_packet.get_reply_icmp_type() == 0:
                valid_data = self.get_data_raw() == icmp_reply_packet.get_reply_icmp_data()
            else:
                valid_data = True

            icmp_reply_packet.set_icmp_data_is_valid(valid_data)

            valid_sequence = self.get_packet_sequence_number() == icmp_reply_packet.get_reply_icmp_sequence_number()
            icmp_reply_packet.set_icmp_sequence_number_is_valid(valid_sequence)

            valid_identifier = self.get_packet_identifier() == icmp_reply_packet.getReplyIcmpIdentifier()
            icmp_reply_packet.set_icmp_identifier_is_valid(valid_identifier)

            packet_validation_bool = (icmp_reply_packet.get_icmp_data_is_valid()
                                    and icmp_reply_packet.get_icmp_sequence_number_is_valid()
                                    and icmp_reply_packet.get_icmp_identifier_is_valid())


            # Set isvalid variable for each based on comparison result
            icmp_reply_packet.set_is_valid_response(packet_validation_bool)


        """Public helper methods."""
        
        def build_packet_echo_request(self, packet_identifier, packet_sequence_number) -> None:
            self.set_icmp_type(8)
            self.set_icmp_code(0)
            self.set_packet_identifier(packet_identifier)
            self.set_packet_sequence_number(packet_sequence_number)
            self.__data_raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__pack_and_recalculate_checksum()

        def send_echo_request(self, is_traceroute :bool=False) ->PingReply|None:
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.set_icmp_target("127.0.0.1")

            mySocket = None

            try:
                if is_traceroute:
                    mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                    headerOffset = 20
                else:
                    mySocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
                    headerOffset = 0

                mySocket.settimeout(self.__ipTimeout)
                mySocket.bind(("", 0))
                mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.get_ttl()))  # Unsigned int - 4 bytes

                if not is_traceroute:
                    actualIdentifier = mySocket.getsockname()[1]    # kernal-assigned port = actual ICMP identifier
                    self.set_packet_identifier(actualIdentifier)

                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeSent = time.time()

                # Set timeLeft to global self.__ipTimeout global variable
                timeLeft = self.__ipTimeout
                whatReady = select.select([mySocket], [], [], timeLeft)

                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")

                while True:
                    recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                    timeReceived = time.time()
                    icmpType, icmpCode = recvPacket[headerOffset:headerOffset + 2]

                    if icmpType == 0:
                        recvIdentifier = struct.unpack("!H", recvPacket[headerOffset + 4:headerOffset + 6])[0]
                    else:
                        ihl = (recvPacket[headerOffset + 8] & 0x0F) * 4
                        recvIdentifier = struct.unpack(
                            "!H",
                            recvPacket[headerOffset + 8 + ihl + 4:headerOffset + 8 + ihl + 6]
                        )[0]

                    # Discard packets that are not responses to sent echo requests
                    if recvIdentifier != self.get_packet_identifier():
                        continue

                    rtt = (timeReceived - timeSent) * 1000

                    # Adjust offset for ICMP type
                    if icmpType == 11:                      # Time exceeded
                        icmp_reply_packet = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket, originalPacket=self,
                                                                                 headerOffset=headerOffset)
                        self.__validate_icmp_reply_packet_with_original_ping_data(icmp_reply_packet)
                        return icmp_reply_packet.toPingReply(self.get_ttl(), rtt, icmpType, icmpCode, addr[0])

                    elif icmpType == 0:                     # Echo reply
                        icmp_reply_packet = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket, originalPacket=self,
                                                                                 headerOffset=headerOffset)
                        self.__validate_icmp_reply_packet_with_original_ping_data(icmp_reply_packet)
                        return icmp_reply_packet.toPingReply(self.get_ttl(), rtt, icmpType, icmpCode, addr[0])

                    elif icmpType == 3:                     # Destination unreachable
                        icmp_reply_packet = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket, originalPacket=self,
                                                                                 headerOffset=headerOffset)
                        self.__validate_icmp_reply_packet_with_original_ping_data(icmp_reply_packet)
                        return icmp_reply_packet.toPingReply(self.get_ttl(), rtt, icmpType, icmpCode, addr[0])

                    else:
                        print("error")

            except timeout:
                return PingReply(sequence_number=self.get_packet_sequence_number(), success=False,
                                 error_message="Request timed out")
            except PermissionError:
                return PingReply(sequence_number=self.get_packet_sequence_number(), success=False,
                                 error_message="Permission denied (raw sockets require sudo)")

            finally:
                if mySocket is not None:
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
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False

        # Create variable for valid identifier
        __icmpData_isValid = False
        __icmpSequenceNumber_isValid = False
        __icmpIdentifier_isValid = False

        """
        Code citation: Trace data which populates these messages adapted from:
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
        # ############################################################################################################ #
        def __init__(self, recvPacket, originalPacket, headerOffset=0):
            self.__recvPacket = recvPacket
            self.__originalPacket = originalPacket
            self.__headerOffset = headerOffset

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        # ############################################################################################################ #
        def get_reply_icmp_type(self):
            return self.__unpackByFormatAndPosition("B", self.__headerOffset + 0)

        def getReplyIcmpCode(self):
            return self.__unpackByFormatAndPosition("B", self.__headerOffset + 1)

        def getReplyIcmpHeaderChecksum(self):
            return self.__unpackByFormatAndPosition("H", self.__headerOffset + 2)

        def getReplyIcmpIdentifier(self):
            return self.__unpackByFormatAndPosition("H", self.__headerOffset + 4)

        def get_reply_icmp_sequence_number(self):
            return self.__unpackByFormatAndPosition("H", self.__headerOffset + 6)

        def getReplyDateTimeSent(self):
            return self.__unpackByFormatAndPosition("d", self.__headerOffset + 8)

        def get_reply_icmp_data(self):
            return self.__recvPacket[self.__headerOffset + 16:].decode('utf-8')

        # _isValid getters
        # getters and setters for icmpIdentifier_isValid and seq number, data
        def get_icmp_data_is_valid(self):
            return self.__icmpData_isValid

        def get_icmp_sequence_number_is_valid(self):
            return self.__icmpSequenceNumber_isValid

        def get_icmp_identifier_is_valid(self):
            return self.__icmpIdentifier_isValid

        def isValidResponse(self):
            return self.__isValidResponse

        # _isValid setters
        def set_icmp_data_is_valid(self, booleanValue):
            self.__icmpData_isValid = booleanValue

        def set_icmp_sequence_number_is_valid(self, booleanValue):
            self.__icmpSequenceNumber_isValid = booleanValue

        def set_icmp_identifier_is_valid(self, booleanValue):
            self.__icmpIdentifier_isValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        # ############################################################################################################ #
        def set_is_valid_response(self, booleanValue):
            self.__isValidResponse = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        # ############################################################################################################ #

        def toPingReply(self, ttl, rtt, icmpType, icmpCode, addr):
            # Check and report errors only for echo response
            if self.get_reply_icmp_type() == 0 and not self.isValidResponse():
                error_parts = []
                if not self.get_icmp_data_is_valid():
                    error_parts.append(
                        f"data mismatch (expected {self.__originalPacket.get_data_raw()!r}, "
                        f"got {self.get_reply_icmp_data()!r})"
                    )
                if not self.get_icmp_sequence_number_is_valid():
                    error_parts.append(
                        f"sequencemismatch (expected {self.__originalPacket.get_packet_sequence_number()},"
                        f"got {self.get_reply_icmp_sequence_number()})"
                    )
                if not self.get_icmp_identifier_is_valid():
                    error_parts.append(
                        f"identifier mismatch (expected {self.__orignialPacket.get_packet_identifier()}, "
                        f"got {self.getReplyIcmpIdentifier()})"
                    )
                return PingReply(
                    sequence_number=self.__originalPacket.get_packet_sequence_number(),
                    success=False,
                    is_valid=False,
                    error_message="; ".join(error_parts),
                )

            code = self.__typeAndCodeMap[icmpType][icmpCode]
            return PingReply(
                sequence_number=self.__originalPacket.get_packet_sequence_number(),
                success=(icmpType == 0),
                rtt_ms=rtt,
                ttl=ttl,
                icmp_type=icmpType,
                icmp_code=code,
                address=addr,
                is_valid=True
            )


    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host, pingCount=4, stop_event=None):
        summary = PingSummary(host=host)
        rttBuffer = []

        for i in range(pingCount):
            if stop_event is not None and stop_event.is_set():
                break

            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            packet_identifier = os.getpid() & 0xffff
            icmpPacket.build_packet_echo_request(packet_identifier, i)
            icmpPacket.set_icmp_target(host)

            reply = icmpPacket.send_echo_request()
            summary.replies.append(reply)

            if reply.success and reply.rtt_ms is not None:
                rttBuffer.append(reply.rtt_ms)

        summary.packets_transmitted = len(summary.replies)
        summary.packets_received = len(rttBuffer)
        summary.packets_lost = summary.packets_transmitted - len(rttBuffer)
        summary.percent_loss = (
            100.0 if summary.packets_transmitted == 0
            else 100.0 * summary.packets_lost / summary.packets_transmitted
        )
        if rttBuffer:
            summary.rtt_min = min(rttBuffer)
            summary.rtt_avg = statistics.mean(rttBuffer)
            summary.rtt_max = max(rttBuffer)

        return summary

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
            icmpPacket.set_ttl(ttl)

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number. Limit based on ICMP header standards
            packet_identifier = randomIdentifier
            packet_sequence_number = i

            icmpPacket.build_packet_echo_request(packet_identifier, packet_sequence_number)  # Build ICMP for IP payload
            icmpPacket.set_icmp_target(host)

            # Get icmpType as return value in order to detect end
            icmpType = icmpPacket.send_echo_request(is_traceroute=True)                     # Build IP

            # Stop immediately if lacking permission to open a raw socket
            if icmpType == "PERMISSION_DENIED":
                print("Traceroute aborted: elevated privileges required.")
                break

            # toggle isEnd if the icmpType is 3 or 0 (type zero returns RTT in send_echo_request() which is a float)
            if icmpType == 3 or icmpType == 0 or isinstance(icmpType, float):
                isEnd = True

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0

            ttl += 1
            i += 1


    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost, pingCount=4, stop_event=None):
        return self.__sendIcmpEchoRequest(targetHost, pingCount, stop_event)

    def traceRoute(self, targetHost:str):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)

    def sendSinglePing(self, host, sequenceNumber):
        """Sends one echo request and returns a single PingReply."""
        icmpPacket = IcmpHelperLibrary.IcmpPacket()
        packet_identifier = os.getpid() & 0xffff
        icmpPacket.build_packet_echo_request(packet_identifier, sequenceNumber)
        icmpPacket.set_icmp_target(host)
        return icmpPacket.send_echo_request()

    @staticmethod
    def summarize(host, replies):
        """Builds a PingSummary from a list of PingReply objects collected so far."""
        summary = PingSummary(host=host)
        rttBuffer = [r.rtt_ms for r in replies if r.success and r.rtt_ms is not None]

        summary.replies = replies
        summary.packets_transmitted = len(replies)
        summary.packets_received = len(rttBuffer)
        summary.packets_lost = summary.packets_transmitted - len(rttBuffer)
        summary.percent_loss = (
            100.0 if summary.packets_transmitted == 0
            else 100.0 * summary.packets_lost / summary.packets_transmitted
        )
        if rttBuffer:
            summary.rtt_min = min(rttBuffer)
            summary.rtt_avg = statistics.mean(rttBuffer)
            summary.rtt_max = max(rttBuffer)

        return summary


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # icmpHelperPing.traceRoute("8.8.8.8")
    icmpHelperPing.sendPing("8.8.8.8")

if __name__ == "__main__":
    main()
