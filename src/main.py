from dataclasses import field
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
                ft.Row(
                    alignment=ft.MainAxisAlignment.CENTER,
                    controls=[
                        ft.Text("Ping", size=30),
                    ],
                ),
                ft.Row(
                    alignment=ft.MainAxisAlignment.CENTER,
                    controls=[
                        ft.Text("Enter a URL or IP address to ping", size=15),
                    ],
                ),
                ft.Row(
                    controls=[
                        self.address,
                        self.ping_button,
                    ],
                ),
                ft.Row(
                    controls=[
                        self.output,
                    ]
                )
            ],
        )

    def ping_clicked(self, e):
        buffer = io.StringIO()
        curr_address = self.address.value
        with redirect_stdout(buffer):
            self.icmp_helper.sendPing(curr_address)
        self.output.value = buffer.getvalue()
        self.update


def main(page: ft.Page):
    page.title = "Ping"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.update()

    # create ping instance
    ping = Ping()

    # add Ping root control to the page
    page.add(ping)







if __name__ == "__main__":
    ft.run(main)
