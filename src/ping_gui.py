import asyncio
import threading
from icmp_ping_backend import IcmpHelperLibrary

import flet as ft

@ft.control
class Ping(ft.Container):
    """
    Graphical interface for sending ICMP ping requests and displaying the
    resulting replies and summary statistics.
    """


    def init(self) -> None:
        """
        Initializes the application's controls, event handlers, and layout.
        """

        self.ping_count = 4                             # Default ping count.
        self.width = 650
        self.padding = ft.Padding.only(top=100)
        self.stop_event = threading.Event()
        self.icmp_helper = IcmpHelperLibrary()
        self._saved_count_value = ""
        self.address = ft.TextField(expand=True)
        self.output = ft.ListView(
            expand=True,
            spacing=2,
            auto_scroll=True,
            width=600,
            height=300,
        )

        # Button for starting ping
        self.ping_button = ft.FloatingActionButton(
            content="Ping",
            on_click=self.ping_clicked
        )

        # Button for stopping ping
        self.stop_button = ft.FilledButton(
            content=ft.Text("Stop"),
            on_click=self.stop_clicked,
            disabled=True,
        )

        # Check-box for specifying pings
        self.count_check_box = ft.Checkbox(
            label="Specify ping count",
            value=False,
            on_change=self.count_changed,
        )

        # Field for entering ping count
        self.count_field = ft.TextField(
            label="Count",
            width=100,
        )

        # Check-box for infinite pings
        self.infinity_check_box = ft.Checkbox(
            label="Ping until stopped",
            value=False,
            on_change=self.infinity_changed,
        )

        # Dropdown for entering ping count and infinity option
        self.count_options_row = ft.Row(
            visible=False,
            controls=[
                ft.Container(width=80),
                self.count_field,
                self.infinity_check_box,
            ]
        )

        # Display fields for GUI
        self.content = ft.SelectionArea(
            content = ft.Column(
                controls = [
                    # Top description
                    ft.Container(
                        padding=ft.Padding.only(right=75),
                        content=ft.Row(alignment=ft.MainAxisAlignment.CENTER,
                                       controls=[ft.Text("Enter a URL or IP address to ping", size=20)]),
                    ),
                    # Address input, ping button and stop button
                    ft.Container(
                        padding=ft.Padding.only(left=50),
                        content=ft.Row(controls=[self.address, self.ping_button, self.stop_button]),
                    ),
                    # Specify ping count check-box
                    ft.Container(
                        padding=ft.Padding.only(left=50),
                        content=ft.Row(alignment=ft.MainAxisAlignment.START, controls=[self.count_check_box]),
                    ),
                    # Count options
                    self.count_options_row,
                    # Output field
                    ft.Container(
                        padding=ft.Padding.only(top=5),
                        content=ft.Row(controls=[ft.Container(width=50), self.output]),
                    ),
                ],
            )
        )

    def infinity_changed(self, e: ft.ControlEvent) -> None:
        """
        Grey out the ping count field when infinite pinging is selected;
        restore its previous value and interactivity when deselected.

        :param e: Checkbox change event.
        """

        if self.infinity_check_box.value:
            self._saved_count_value = self.count_field.value
            self.count_field.disabled = True
        else:
            self.count_field.value = self._saved_count_value
            self.count_field.disabled = False
        self.update()

    def count_changed(self, e: ft.ControlEvent) -> None:
        """
        Show or hide ping count controls.

        :param e: Checkbox change event.
        """

        self.count_options_row.visible = self.count_check_box.value
        self.update()


    async def ping_clicked(self, e: ft.ControlEvent) -> None:
        """
        Send ICMP Echo Requests and display the results.

        Runs the ping operation asynchronously, updates the interface as each
        reply is received, and displays summary statistics when the operation
        completes or is stopped by the user.

        :param e: The button click event.
        """

        self.stop_event.clear()

        host = self.address.value

        if not host or not host.strip():
            self.output.controls.clear()
            self.output.controls.append(ft.Text("Enter a host or IP address to ping.", color=ft.Colors.RED))
            self.update()
            return

        infinite = self.infinity_check_box.value

        if not infinite and self.count_check_box.value:
            if self.count_field.value and self.count_field.value.strip().isdigit():
                self.ping_count = int(self.count_field.value.strip())
            else:
                self.output.controls.clear()
                self.output.controls.append(ft.Text("Enter a valid ping count.", color=ft.Colors.RED))
                self.update()
                return

        elif not infinite:
            self.ping_count = 4

        self.ping_button.disabled = True
        self.stop_button.disabled = False
        self.output.controls.clear()
        self.output.controls.append(ft.Text("Pinging..."))
        self.update()

        replies = []
        seq = 0
        self.output.controls.clear()

        while True:
            if self.stop_event.is_set():
                break
            if not infinite and seq >= self.ping_count:
                break

            reply = await asyncio.to_thread(self.icmp_helper.send_single_ping, host, seq)
            replies.append(reply)

            if reply.success:
                text = f"seq={reply.sequence_number} ttl={reply.ttl} rtt={reply.rtt_ms:.0f}ms {reply.address}"
                color = ft.Colors.GREEN
            else:
                text = f"seq={reply.sequence_number} {reply.error_message or 'failed'}"
                color = ft.Colors.RED
            self.output.controls.append(ft.Text(text, color=color))
            self.update()  # <-- render this reply immediately, don't wait for the rest

            seq += 1

        summary = self.icmp_helper.summarize(host, replies)

        self.output.controls.append(ft.Divider())
        self.output.controls.append(ft.Text(
            f"{summary.packets_transmitted} sent, {summary.packets_received} received, "
            f"{summary.percent_loss:.0f}% loss"
        ))
        if summary.rtt_avg is not None:
            self.output.controls.append(ft.Text(
                f"rtt min/avg/max = {summary.rtt_min:.0f}/{summary.rtt_avg:.0f}/{summary.rtt_max:.0f} ms"
            ))
        if self.stop_event.is_set():
            self.output.controls.append(ft.Text("Stopped by user.", color=ft.Colors.AMBER))

        self.ping_button.disabled = False
        self.stop_button.disabled = True
        self.update()


    def stop_clicked(self, e: ft.ControlEvent) -> None:
        """
        Stop the current ping operation.

        Signals the running ping loop to terminate and disables the Stop button.

        :param e: Stop button click event.
        """

        self.stop_event.set()
        self.stop_button.disabled = True
        self.update()


def main(page: ft.Page) -> None:
    """
    Configure and initialize the application's main page.

    :param page: The Flet page that hosts the application.
    """

    page.title = "ICMP Ping GUI"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.add(Ping())


if __name__ == "__main__":
    ft.run(main)
