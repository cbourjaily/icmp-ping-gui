
    def ping_clicked(self, e):
        self.output.controls.clear()
        curr_address = self.address.value

        summary = self.icmp_helper.sendPing(curr_address)

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
            f"{summary.packets_transmitted} sent, {summary.packets_received} received, "
            f"{summary.percent_loss:.0f}% loss"
        ))
        if summary.rtt_avg is not None:
            self.output.controls.append(ft.Text(
                f"rtt min/avg/max = {summary.rtt_min:.0f}/{summary.rtt_avg:.0f}/{summary.rtt_max:.0f} ms"
            ))

        self.update()


def main(page: ft.Page):
    page.title = "Ping"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.add(Ping())


if __name__ == "__main__":
    ft.run(main)