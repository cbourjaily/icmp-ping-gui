from dataclasses import field
from IcmpHelperLibrary import IcmpHelperLibrary

import flet as ft

@ft.control
class Ping(ft.Column):
    def init(self):
        self.input = ft.TextField(expand=True)
        self.button = ft.FloatingActionButton(
            content="Ping",
            on_click=self.ping_clicked
        )
        self.width = 400
        self.controls = [
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
                    self.input,
                    self.button,
                ],
            ),
        ]

    def ping_clicked(self, e):
        pass


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
