import flet as ft


def main(page: ft.Page):
    page.theme_mode = ft.ThemeMode.LIGHT

    page.add(
        ft.SafeArea(
            content=ft.CupertinoSegmentedButton(
                selected_index=1,
                selected_color=ft.Colors.BLUE,
                on_change=lambda e: print(f"selected_index: {e.data}"),
                padding=ft.Padding.symmetric(vertical=20, horizontal=50),
                width=1000,
                controls=[
                    ft.Text("Ping"),
                    ft.Container(
                        padding=ft.Padding.symmetric(vertical=10, horizontal=30),
                        content=ft.Text("Traceroute"),
                    ),
                ],
            ),
        )
    )


if __name__ == "__main__":
    ft.run(main)