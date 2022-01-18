from app import app
from flask_apscheduler import APScheduler
from Utils.utils import remove_tickets

scheduler = APScheduler()

if __name__ == "__main__":
    scheduler.add_job(
        id="Delete tickets", func=remove_tickets, trigger="interval", seconds=5
    )
    scheduler.start()
    app.run()
