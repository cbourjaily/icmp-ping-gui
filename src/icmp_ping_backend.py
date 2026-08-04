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
import select
import statistics
import struct
import threading
import time
from socket import AF_INET, IPPROTO_ICMP, IPPROTO_IP, IP_TTL, SOCK_DGRAM, SOCK_RAW, gethostbyname, socket, timeout

# For GUI integration
from typing import Optional, List
from dataclasses import dataclass, field


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

    __debug_enabled = False


    class IcmpPacket:
        """
        Represents an ICMP packet and provides methods for constructing, sending,
        and validating ICMP Echo Request and Echo Reply messages.

        References:
            https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
        """

        # IcmpPacket Class Scope Variables
        __icmp_target = ""                # Destination hostname or IP address.
        __destination_ip_address = ""     # Resolved destination IP address.
        __header = b''                    # Packed ICMP header.
        __data = b''                      # Encoded ICMP payload.
        __data_raw = ""                   # Payload before encoding.
        __icmp_type = 0
        __icmp_code = 0
        __packet_checksum = 0
        __packet_identifier = 0
        __packet_sequence_number = 0
        __ip_timeout = 5                  # Socket timeout (seconds)
        __ttl = 255                       # IP time-to-live
        __debug_enabled = False           # Enable diagnostic output


        """Getter methods."""

        def get_icmp_target(self) -> str:
            return self.__icmp_target

        def get_data_raw(self) -> str:
            return self.__data_raw

        def get_icmp_type(self) -> int:
            return self.__icmp_type

        def get_icmp_code(self) -> int:
            return self.__icmp_code

        def get_packet_checksum(self) -> int:
            return self.__packet_checksum

        def get_packet_identifier(self) -> int:
            return self.__packet_identifier

        def get_packet_sequence_number(self) -> int:
            return self.__packet_sequence_number

        def get_ttl(self) -> int:
            return self.__ttl


        """Setter methods."""

        def set_icmp_target(self, icmp_target: str) -> None:
            self.__icmp_target = icmp_target

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmp_target.strip()) > 0:
                self.__destination_ip_address = gethostbyname(self.__icmp_target.strip())

        def set_icmp_type(self, icmp_type: int) -> None:
            self.__icmp_type = icmp_type

        def set_icmp_code(self, icmp_code: int) -> None:
            self.__icmp_code = icmp_code

        def set_packet_checksum(self, packet_checksum: int) -> None:
            self.__packet_checksum = packet_checksum

        def set_packet_identifier(self, packet_identifier: int)-> None:
            self.__packet_identifier = packet_identifier

        def set_packet_sequence_number(self, sequence_number: int) -> None:
            self.__packet_sequence_number = sequence_number

        def set_ttl(self, ttl: int) -> None:
            self.__ttl = ttl


        """Private helper methods."""

        def __recalculate_checksum(self) -> None:
            """
            Compute and update the ICMP checksum for the current packet.

            Calculates the Internet checksum over the packet header and payload
            using the one's complement checksum algorithm defined for ICMP.
            """

            print("calculateChecksum Started...") if self.__debug_enabled else 0
            packet_as_byte_data = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            count_to = (len(packet_as_byte_data) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__debug_enabled else 0
            count = 0
            while count < count_to:
                this_val = packet_as_byte_data[count + 1] * 256 + packet_as_byte_data[count]
                checksum = checksum + this_val
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(this_val):10} {hex(checksum):10}') if self.__debug_enabled else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if count_to < len(packet_as_byte_data):
                this_val = packet_as_byte_data[len(packet_as_byte_data) - 1]
                checksum = checksum + this_val
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(this_val), "\t", hex(checksum)) if self.__debug_enabled else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add
            answer = ~checksum                                  # Invert bits
            answer = answer & 0xffff                            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__debug_enabled else 0

            self.set_packet_checksum(answer)


        def __pack_header(self) -> None:
            """
            Pack the ICMP header fields into their binary representation.
            """

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


        def __encode_data(self) -> None:
            """
            Construct the ICMP payload.

            Encodes the user data as UTF-8 and prefixes it with an 8-byte
            timestamp used to calculate round-trip time.
            """

            data_time = struct.pack("<d", time.time())           # time.time() creates a 64 bit value of 8 bytes
            data_raw_encoded = self.get_data_raw().encode("utf-8")
            self.__data = data_time + data_raw_encoded


        def __pack_and_recalculate_checksum(self) -> None:
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

            valid_identifier = self.get_packet_identifier() == icmp_reply_packet.get_reply_icmp_identifier()
            icmp_reply_packet.set_icmp_identifier_is_valid(valid_identifier)

            packet_validation_bool = (icmp_reply_packet.get_icmp_data_is_valid()
                                    and icmp_reply_packet.get_icmp_sequence_number_is_valid()
                                    and icmp_reply_packet.get_icmp_identifier_is_valid())


            # Set isvalid variable for each based on comparison result
            icmp_reply_packet.set_is_valid_response(packet_validation_bool)


        """Public helper methods."""
        
        def build_packet_echo_request(self, packet_identifier, packet_sequence_number) -> None:
            """
            Build an ICMP echo request packet.

            :param packet_identifier: Unique identifier used to match replies to this request.
            :param packet_sequence_number: Sequence number for the Echo Request packet.
            """

            self.set_icmp_type(8)
            self.set_icmp_code(0)
            self.set_packet_identifier(packet_identifier)
            self.set_packet_sequence_number(packet_sequence_number)
            self.__data_raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__pack_and_recalculate_checksum()


        def send_echo_request(self, is_traceroute :bool=False) -> PingReply | None:
            """
            Send an ICMP Echo Request and process the reply.

            :param is_traceroute:
                If True, send the request using a raw socket for traceroute.
                Otherwise, use a datagram ICMP socket for standard ping.
            :return:
                A PingReply describing the received response, or None if no
                matching reply is received.
            """

            if not self.__icmp_target.strip() or not self.__destination_ip_address.strip():
                raise ValueError("ICMP target address is not set.")

            my_socket = None

            try:
                if is_traceroute:
                    my_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
                    header_offset = 20
                else:
                    my_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)
                    header_offset = 0

                my_socket.settimeout(self.__ip_timeout)
                my_socket.bind(("", 0))
                my_socket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.get_ttl()))  # Unsigned int - 4 bytes

                if not is_traceroute:
                    actual_identifier = my_socket.getsockname()[1]    # kernal-assigned port = actual ICMP identifier
                    self.set_packet_identifier(actual_identifier)

                my_socket.sendto(b''.join([self.__header, self.__data]), (self.__destination_ip_address, 0))
                time_sent = time.time()

                # Set time_left to global self.__ip_timeout global variable
                time_left = self.__ip_timeout
                what_ready = select.select([my_socket], [], [], time_left)

                if what_ready[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")

                while True:
                    recv_packet, addr = my_socket.recvfrom(1024)  # recv_packet - bytes object representing data received
                    time_received = time.time()
                    icmp_type, icmp_code = recv_packet[header_offset:header_offset + 2]

                    if icmp_type == 0:
                        recv_identifier = struct.unpack("!H", recv_packet[header_offset + 4:header_offset + 6])[0]
                    else:
                        ihl = (recv_packet[header_offset + 8] & 0x0F) * 4
                        recv_identifier = struct.unpack(
                            "!H",
                            recv_packet[header_offset + 8 + ihl + 4:header_offset + 8 + ihl + 6]
                        )[0]

                    # Discard packets that are not responses to sent echo requests
                    if recv_identifier != self.get_packet_identifier():
                        continue

                    rtt = (time_received - time_sent) * 1000

                    # Adjust offset for ICMP type
                    if icmp_type == 11:                      # Time exceeded
                        icmp_reply_packet = IcmpHelperLibrary.IcmpPacket_EchoReply(recv_packet, original_packet=self,
                                                                                 header_offset=header_offset)
                        self.__validate_icmp_reply_packet_with_original_ping_data(icmp_reply_packet)
                        return icmp_reply_packet.to_ping_reply(self.get_ttl(), rtt, icmp_type, icmp_code, addr[0])

                    elif icmp_type == 0:                     # Echo reply
                        icmp_reply_packet = IcmpHelperLibrary.IcmpPacket_EchoReply(recv_packet, original_packet=self,
                                                                                 header_offset=header_offset)
                        self.__validate_icmp_reply_packet_with_original_ping_data(icmp_reply_packet)
                        return icmp_reply_packet.to_ping_reply(self.get_ttl(), rtt, icmp_type, icmp_code, addr[0])

                    elif icmp_type == 3:                     # Destination unreachable
                        icmp_reply_packet = IcmpHelperLibrary.IcmpPacket_EchoReply(recv_packet, original_packet=self,
                                                                                 header_offset=header_offset)
                        self.__validate_icmp_reply_packet_with_original_ping_data(icmp_reply_packet)
                        return icmp_reply_packet.to_ping_reply(self.get_ttl(), rtt, icmp_type, icmp_code, addr[0])

                    else:
                        print("error")

            except timeout:
                return PingReply(sequence_number=self.get_packet_sequence_number(), success=False,
                                 error_message="Request timed out")
            except PermissionError:
                return PingReply(sequence_number=self.get_packet_sequence_number(), success=False,
                                 error_message="Permission denied (raw sockets require sudo)")

            finally:
                if my_socket is not None:
                    my_socket.close()


        def print_icmp_packet_header_hex(self) -> None:
            """
            Print the ICMP packet header in hexadecimal format.
            """

            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())


        def printIcmp_packet_data_hex(self) -> None:
            """
            Print the ICMP packet payload in hexadecimal format.
            """

            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())


        def print_icmp_packet_hex(self) -> None:
            """
            Print the complete ICMP packet in hexadecimal format.
            """

            print("Printing packet in hex...")
            self.print_icmp_packet_header_hex()
            self.printIcmp_packet_data_hex()


    class IcmpPacket_EchoReply:
        """
        Represents an ICMP Echo Reply packet received from a remote host.

        Provides methods for parsing ICMP reply packets, validating their contents against
        the original Echo Request, and converting the results into a PingReply object.
        """
        
        """Class atributes."""

        __recv_packet = b""
        __matches_original_request = False

        # Create variable for valid identifier
        __icmp_data_is_valid = False
        __icmp_sequence_number_is_valid = False
        __icmp_identifier_is_valid = False
        __debug_echo_reply = False  # Allows for debug output

        # ICMP type and code descriptions adapted from:
        # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
        __type_and_code_map = {               # { type : { code : `trace statement` } }
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


        """Constructors."""

        def __init__(self, recv_packet: bytes, original_packet: "IcmpPacket", header_offset: int = 0) -> None:
            self.__recv_packet = recv_packet
            self.__original_packet = original_packet
            self.__header_offset = header_offset


        """IcmpPacket_EchoReply Getters."""

        def get_reply_icmp_type(self) -> int:
            return self.__unpack_by_format_and_position("B", self.__header_offset + 0)

        def get_reply_icmp_code(self) -> int:
            return self.__unpack_by_format_and_position("B", self.__header_offset + 1)

        def get_reply_icmp_header_checksum(self) -> int:
            return self.__unpack_by_format_and_position("H", self.__header_offset + 2)

        def get_reply_icmp_identifier(self) -> int:
            return self.__unpack_by_format_and_position("H", self.__header_offset + 4)

        def get_reply_icmp_sequence_number(self) -> int:
            return self.__unpack_by_format_and_position("H", self.__header_offset + 6)

        def get_reply_date_time_sent(self) -> float:
            return self.__unpack_by_format_and_position("d", self.__header_offset + 8)

        def get_reply_icmp_data(self) -> str:
            return self.__recv_packet[self.__header_offset + 16:].decode('utf-8')

        def get_icmp_data_is_valid(self) -> bool:
            return self.__icmp_data_is_valid

        def get_icmp_sequence_number_is_valid(self) -> bool:
            return self.__icmp_sequence_number_is_valid

        def get_icmp_identifier_is_valid(self) -> bool:
            return self.__icmp_identifier_is_valid

        def matches_original_request(self) -> bool:
            return self.__matches_original_request


        """IcmpPacket_EchoReply Setters."""

        def set_icmp_data_is_valid(self, boolean_value: bool) -> None:
            self.__icmp_data_is_valid = boolean_value

        def set_icmp_sequence_number_is_valid(self, boolean_value: bool) -> None:
            self.__icmp_sequence_number_is_valid = boolean_value

        def set_icmp_identifier_is_valid(self, boolean_value: bool) -> None:
            self.__icmp_identifier_is_valid = boolean_value

        def set_is_valid_response(self, boolean_value: bool) -> None:
            self.__matches_original_request = boolean_value

        
        """IcmpHelperLibrary private helper methods."""

        def __unpack_by_format_and_position(self, format_code: str, base_position: int) -> bytes:
            """
            Unpack a value from the received packet.

            :param format_code: Struct format code used to unpack the value.
            :param base_position: Byte offset within the received packet.
            :return: The unpacked value.
            """

            number_of_bytes = struct.calcsize(format_code)
            return struct.unpack(
                "!" + format_code,
                self.__recv_packet[base_position:base_position + number_of_bytes])[0]


        """IcmpPacket_EchoReply public helper methods."""

        def to_ping_reply(self, ttl: int, rtt: float, icmp_type: int, icmp_code: int, addr: str) -> PingReply:
            """
            Convert the received ICMP packet into a PingReply object.

            :param ttl: Time-to-live (TTL) value associated with the reply.
            :param rtt: Round-trip time (RTT) in milliseconds.
            :param icmp_type: ICMP message type.
            :param icmp_code: ICMP message code.
            :param addr: IP address of the responding host.
            :return: A PingReply representing the processed ICMP response.
            """

            # Check and report errors only for echo response
            if self.get_reply_icmp_type() == 0 and not self.matches_original_request():
                error_parts = []
                if not self.get_icmp_data_is_valid():
                    error_parts.append(
                        f"data mismatch (expected {self.__original_packet.get_data_raw()!r}, "
                        f"got {self.get_reply_icmp_data()!r})"
                    )
                if not self.get_icmp_sequence_number_is_valid():
                    error_parts.append(
                        f"sequence mismatch (expected {self.__original_packet.get_packet_sequence_number()},"
                        f"got {self.get_reply_icmp_sequence_number()})"
                    )
                if not self.get_icmp_identifier_is_valid():
                    error_parts.append(
                        f"identifier mismatch (expected {self.__original_packet.get_packet_identifier()}, "
                        f"got {self.get_reply_icmp_identifier()})"
                    )
                return PingReply(
                    sequence_number=self.__original_packet.get_packet_sequence_number(),
                    success=False,
                    is_valid=False,
                    error_message="; ".join(error_parts),
                )

            icmp_code_description = self.__type_and_code_map[icmp_type][icmp_code]
            return PingReply(
                sequence_number=self.__original_packet.get_packet_sequence_number(),
                success=(icmp_type == 0),
                rtt_ms=rtt,
                ttl=ttl,
                icmp_type=icmp_type,
                icmp_code=icmp_code_description,
                address=addr,
                is_valid=True
            )


    """IcmpPacket_EchoReply Private helper methods."""

    def __send_icmp_echo_request(
            self,
            host,
            ping_count: int=4,
            stop_event: threading.Event | None = None
    ) -> PingSummary:
        """
        Send one or more ICMP Echo Requests to the specified host.
        
        Collects individual PingReply objects and returns a PingSummary object containing
        packet statistics and round-trip time measurements.

        :param host: Hostname or IP address to ping.
        :param ping_count: Number of Echo Requests to send.
        :param stop_event: Optional threading.Event to terminate the ping sequence early.
        :return: A PingSummary containing the collected ping results.
        """
        
        summary = PingSummary(host=host)
        rtt_buffer = []

        for i in range(ping_count):
            if stop_event is not None and stop_event.is_set():
                break

            icmp_packet = IcmpHelperLibrary.IcmpPacket()
            packet_identifier = os.getpid() & 0xffff
            icmp_packet.build_packet_echo_request(packet_identifier, i)
            icmp_packet.set_icmp_target(host)

            reply = icmp_packet.send_echo_request()
            summary.replies.append(reply)

            if reply.success and reply.rtt_ms is not None:
                rtt_buffer.append(reply.rtt_ms)

        summary.packets_transmitted = len(summary.replies)
        summary.packets_received = len(rtt_buffer)
        summary.packets_lost = summary.packets_transmitted - len(rtt_buffer)
        summary.percent_loss = (
            100.0 if summary.packets_transmitted == 0
            else 100.0 * summary.packets_lost / summary.packets_transmitted
        )
        if rtt_buffer:
            summary.rtt_min = min(rtt_buffer)
            summary.rtt_avg = statistics.mean(rtt_buffer)
            summary.rtt_max = max(rtt_buffer)

        return summary


    """
    Code citation:
    While implementing this method, I referred to the `traceroute.c` source
    file distributed in `traceroute.tar.Z` from ftp.ee.lbl.gov as a reference
    for the traceroute algorithm and packet processing logic.
    """

    def __send_icmp_traceroute(self, host: str) -> None:
        """
        Perform an ICMP-based traceroute to the specified host.

        Sends ICMP Echo Requests with progressively increasing TTL values to
        discover each hop along the network path until the destination is
        reached or the maximum TTL is exceeded.

        :param host: Hostname or IP address of the destination.
        :return: None.
        """
        
        print("send_icmp_traceroute Started...") if self.__debug_enabled else 0

        print(f"Traceroute to ({host}) {host}")

        # Loop while code 11 time exceeded replies are received and code 3 destination unreachable are not
        is_end = False       # Flag for destination reached indicated by type 3
        ttl = 1               # For incrementing TTL
        i = 0                   # For sequence number
        max_ttl = 30

        while not is_end and ttl <= max_ttl:
             # Build packet
            icmp_packet = IcmpHelperLibrary.IcmpPacket()

             # Set TTL
            icmp_packet.set_ttl(ttl)

            random_identifier = (os.getpid() & 0xffff)      # Get as 16 bit number. Limit based on ICMP header standards
            packet_identifier = random_identifier
            packet_sequence_number = i

            icmp_packet.build_packet_echo_request(packet_identifier, packet_sequence_number)  # Build ICMP for IP payload
            icmp_packet.set_icmp_target(host)

            # Get icmp_type as return value in order to detect end
            icmp_type = icmp_packet.send_echo_request(is_traceroute=True)                     # Build IP

            # Stop immediately if lacking permission to open a raw socket
            if icmp_type == "PERMISSION_DENIED":
                print("Traceroute aborted: elevated privileges required.")
                break

            # toggle is_end if the icmp_type is 3 or 0 (type zero returns RTT in send_echo_request() which is a float)
            if icmp_type == 3 or icmp_type == 0 or isinstance(icmp_type, float):
                is_end = True

            icmp_packet.print_icmp_packet_header_hex() if self.__debug_enabled else 0
            icmp_packet.print_icmp_packet_hex() if self.__debug_enabled else 0

            ttl += 1
            i += 1


    """IcmpHelperLibrary public helper methods."""

    def send_ping(self, target_host: str, ping_count: int=4, stop_event: threading.Event | None = None) -> PingSummary:
        """
        Send one or more ICMP Echo Requests to a target host.

        :param target_host: Hostname or IP address to ping.
        :param ping_count: Number of Echo Requests to send.
        :param stop_event: Optional event used to stop the ping operation before completion.
        :return: A PingSummary containing the results of the ping operation.
        """

        return self.__send_icmp_echo_request(target_host, ping_count, stop_event)


    def traceroute(self, target_host:str) -> None:
        """
        Perform an ICMP-based traceroute to the specified host.

        Sends ICMP Echo Requests with increasing TTL values to identify the
        network path between the local machine and the destination host.

        :param target_host: Hostname or IP address of the destination.
        :return: None.
        """

        print("traceroute Started...") if self.__debug_enabled else 0
        self.__send_icmp_traceroute(target_host)


    def send_single_ping(self, host:str, sequence_number:int) -> PingReply | None:
        """
        Send a single ICMP Echo Request.

        :param host: Hostname or IP address to ping.
        :param sequence_number: Sequence number assigned to the Echo Request.
        :return: The PingReply for the received response, or None if no reply is returned.
        """

        icmp_packet = IcmpHelperLibrary.IcmpPacket()
        packet_identifier = os.getpid() & 0xffff
        icmp_packet.build_packet_echo_request(packet_identifier, sequence_number)
        icmp_packet.set_icmp_target(host)
        return icmp_packet.send_echo_request()


    @staticmethod
    def summarize(host: str, ping_replies: list[PingReply]) -> PingSummary:
        """
        Build a PingSummary from a collection of PingReply objects.

        Calculates packet statistics and round-trip time metrics for the
        supplied ping results.

        :param host: Hostname or IP address that was pinged.
        :param replies: List of PingReply objects collected during the ping operation.
        :return: A PingSummary containing packet and timing statistics.
        """

        summary = PingSummary(host=host)
        rtt_buffer = [r.rtt_ms for r in ping_replies if r.success and r.rtt_ms is not None]

        summary.replies = ping_replies
        summary.packets_transmitted = len(ping_replies)
        summary.packets_received = len(rtt_buffer)
        summary.packets_lost = summary.packets_transmitted - len(rtt_buffer)
        summary.percent_loss = (
            100.0 if summary.packets_transmitted == 0
            else 100.0 * summary.packets_lost / summary.packets_transmitted
        )
        if rtt_buffer:
            summary.rtt_min = min(rtt_buffer)
            summary.rtt_avg = statistics.mean(rtt_buffer)
            summary.rtt_max = max(rtt_buffer)

        return summary


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()

    # icmpHelperPing.traceroute("8.8.8.8")
    icmpHelperPing.send_ping("8.8.8.8")

if __name__ == "__main__":
    main()
