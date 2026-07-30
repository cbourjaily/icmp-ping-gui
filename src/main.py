from dataclasses import field
import asyncio
from IcmpHelperLibrary import IcmpHelperLibrary

import flet as ft

@ft.control
class Ping(ft.Container):

    def init(self):
        self.icmp_helper = IcmpHelperLibrary()
        self.address = ft.TextField(expand=True)
        self.output = ft.ListView(
            expand=True,
            spacing=2,
            auto_scroll=True,
            width=600,
        )
        self.ping_button = ft.FloatingActionButton(
            content="Ping",
            on_click=self.ping_clicked
        )
        self.width = 400
        self.content = ft.Column(
            controls = [
                ft.Row(alignment=ft.MainAxisAlignment.CENTER, controls=[ft.Text("Ping", size=30)]),
                ft.Row(alignment=ft.MainAxisAlignment.CENTER,
                    controls=[ft.Text("Enter a URL or IP address to ping", size=15)]),
                ft.Row(controls=[self.address, self.ping_button]),
                ft.Row(controls=[self.output]),
            ],
        )

    async def ping_clicked(self, e):
        self.ping_button.disabled = True
        self.output.controls.clear()
        self.output.controls.append(ft.Text("Pinging..."))
        self.update()

        curr_address = self.address.value

        summary = await asyncio.to_thread(self.icmp_helper.sendPing, curr_address)

        self.output.controls.clear
        for reply in summary.replies:
            if reply.success:
                text = f"seq={reply.sequence_number} ttl={reply.ttl} rtt={reply.rtt_ms:.0f}ms {reply.address}"
                color = ft.Colors.GREEN
            else:
                text = f"seq={reply.sequence_number} {reply.error_message or 'failed'}"
                color = ft.Colors.RED
            self.output.controls.append(ft.Text(text, color=color))

        self.output.controls.append(ft.Divider())
        self.output.controls.append(ft.Text(
            f"{summary.packets_transmitted} sent, {summary.packets_received} = received, "
            f"{summary.percent_loss:.0f}% loss"
        ))
        if summary.rtt_avg is not None:
            self.output.controls.append(ft.Text(
                f"rtt min/avg/max = {summary.rtt_min:.0f}/{summary.rtt_avg:.0f}/{summary.rtt_max:.0f} ms"
            ))

        self.ping_button.disabled = False
        self.update()


def main(page: ft.Page):
    page.title = "Ping"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.add(Ping())







if __name__ == "__main__":
    ft.run(main)
