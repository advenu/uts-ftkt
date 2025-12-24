import json

from mitmproxy.http import HTTPFlow

def response(flow: HTTPFlow) -> None:
    if (
        "/pfwsa2/profile/syncTicket_v2" in flow.request.path
        and flow.response.headers["Content-Type"] == "application/json"
    ):
        flow.intercept()

        tickets = json.loads(flow.response.get_text())
        ticket = tickets[0]

        if ticket["respCode"] != 0:
            print("No valid ticket found")
            flow.resume()
            return

        # ticket_enc_data = ticket["encrypted"]
        # parts = ticket_enc_data.split("#")

        # parts[2] = "90A40B6624BF57461297F81028616FFF4C5DBDDBF55C5C2117A3F8F45F42388E"

        # ticket_enc_data = "#".join(parts)
        # ticket["encrypted"] = ticket_enc_data
        # tickets[0] = ticket

        with open("fake_ticket.json") as f:
            fake_tickets = json.load(f)

        tickets[0] = fake_tickets[0]

        flow.response.set_text(json.dumps(tickets))

        print("Modified request")
        flow.resume()
