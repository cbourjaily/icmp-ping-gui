from dataclasses import field
import asyncio
import threading
from IcmpHelperLibrary import IcmpHelperLibrary

import flet as ft

@ft.control
class Ping(ft.Container):

    def init(self):
        self.ping_count = 4
        self.stop_event = threading.Event()
        self.icmp_helper = IcmpHelperLibrary()
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
        # button for stopping ping
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
        # checkbox for infinite pings
        self.infinity_check_box = ft.Checkbox(
            label="Ping until stopped",
            value=False,
        )
        self.count_options_row = ft.Row(
            visible=False,
            controls=[
                ft.Container(width=80),
                self.count_field,
                self.infinity_check_box,
            ]
        )
        self.width = 520
        self.content = ft.SelectionArea(
            content = ft.Column(
                controls = [
                    ft.Row(alignment=ft.MainAxisAlignment.CENTER, controls=[ft.Text("Ping", size=30)]),
                    ft.Row(alignment=ft.MainAxisAlignment.CENTER,
                        controls=[ft.Text("Enter a URL or IP address to ping", size=15)]),
                    ft.Row(
                        controls=[ft.Container(width=50), self.address, self.ping_button, self.stop_button]),
                    ft.Row(alignment=ft.MainAxisAlignment.START,
                           controls=[ft.Container(width=50), self.count_check_box]),
                    self.count_options_row,
                    ft.Row(controls=[self.output]),
                ],
            )
        )


    """
    Makes available options for entering ping count.
    """

    def count_changed(self, e):
        self.count_options_row.visible = self.count_check_box.value
        self.update()

    """
    Starts ping sequence.
    """

    async def ping_clicked(self, e):
        self.stop_event.clear()

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

        curr_address = self.address.value
        replies = []
        seq = 0

        self.output.controls.clear()
        while True:
            if self.stop_event.is_set():
                break
            if not infinite and seq >= self.ping_count:
                break

            reply = await asyncio.to_thread(self.icmp_helper.sendSinglePing, curr_address, seq)
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

        summary = self.icmp_helper.summarize(curr_address, replies)

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

    """
    Signals ongoing ping to stop running.
    """
    def stop_clicked(self, e):
        self.stop_event.set()
        self.stop_button.disabled = True
        self.update()


def main(page: ft.Page):
    page.title = "Ping"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.add(Ping())







if __name__ == "__main__":
    ft.run(main)
