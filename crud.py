import sqlite3
from datetime import datetime
import os
from get_choice.chooser import get_choice

from gen_ticket import calc_validity, create_fake_ticket, read_ticket


def crud_application(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    while True:
        choice = get_choice(
            ["List Tickets", "Add Ticket", "Delete Ticket", "Exit"],
            title="Fake Ticket Generator",
            msg="Choose an action",
            get_int=True,
        )
        if choice == 1:
            cursor.execute("SELECT VALID_UPTO, DATA, TKT_TYPE, ID FROM TICKET")
            tickets = cursor.fetchall()
            if tickets:
                print(f"\nFound {len(tickets)} ticket(s):\n")
                for ticket in tickets:
                    print("Ticket ID:", ticket[3])
                    print(read_ticket(ticket[1]))  # ticket[1] is DATA
            else:
                print("\nNo tickets found.")

        elif choice == 2:
            print("\nEnter details for the new ticket (press Enter for defaults):")
            src = input("Source: ") or "SRC"
            dst = input("Destination: ") or "DST"
            via = input("Via (default: ---): ") or "---"
            dist = int(input("Distance: ") or 0)
            cost = int(input("Cost: ") or 0)
            train_type = input("Train Type (O|M/E) (default: M/E): ") or "M/E"
            person = int(input("Number of Persons (default: 1): ") or 1)

            user_dt_str = input("Datetime (default: current): ")
            if user_dt_str:
                dt = datetime.strptime(user_dt_str, "%d/%m/%Y %H:%M:%S")
            else:
                dt = datetime.now()
            valid_upto = calc_validity(dt)

            ticket_data = create_fake_ticket(
                src, dst, via, dist, cost, train_type, dt, person
            )
            cursor.execute(
                "INSERT INTO TICKET (VALID_UPTO, DATA, TKT_TYPE) VALUES (?, ?, ?)",
                (valid_upto.strftime("%Y-%m-%d %H:%M:%S"), ticket_data, "J"),
            )
            conn.commit()
            print("\nTicket added successfully.")

        elif choice == 3:
            ticket_id = input("\nEnter the ID of the ticket to delete: ")
            if ticket_id.isdigit():
                cursor.execute("DELETE FROM TICKET WHERE ID = ?", (ticket_id,))
                if cursor.rowcount > 0:
                    conn.commit()
                    print("\nTicket deleted successfully.")
                else:
                    print("\nTicket not found.")
            else:
                print("\nInvalid ID.")

        elif choice == 4:
            print("Exiting Fake Ticket Generator. Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")

    conn.close()


# Run the application
db_path = "MUTS_DB"

if not os.getenv("DEBUG"):
    db_path = f"/data/data/com.cris.utsmobile/databases/{db_path}"

if not os.path.exists(db_path):
    raise FileNotFoundError(f"Database file '{db_path}' not found.")

crud_application(db_path)
