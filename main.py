from crud import crud_application
import os

def main():
    # print("Fake Ticket Generator")

    # Run the application
    db_path = "MUTS_DB"

    if not os.getenv("DEBUG"):
        db_path = f"/data/data/com.cris.utsmobile/databases/{db_path}"

    if not os.path.exists(db_path):
        raise FileNotFoundError(f"Database file '{db_path}' not found.")
    
    crud_application(db_path)


if __name__ == "__main__":
    main()
