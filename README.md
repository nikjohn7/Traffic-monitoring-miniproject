# Traffic Monitoring Web Application

This project involved developing a web application with Python and Flask to enable traffic data collection and analysis.

## Description

The application provides a front-end UI built with HTML, CSS and JavaScript that interacts with a Python Flask backend API. The backend handles user management, tracks sessions, allows adding and removing traffic entries, generates statistics, and exports CSV summary reports. Data is stored in an sqlite database.

Key features:

- User login with session tracking
-  Recording vehicle entries with location, type and occupancy
- Undoing entries to correct mistakes
- Live summarization of traffic statistics
- Exporting full traffic and user hour summaries as CSV files

The backend API passes an extensive automated testing suite to validate functionality.

## Usage

The backend Flask server can be started as:
```bash
python server.py


```
The front-end UI is then accessible at http://localhost:5000

Users can create accounts and login to start a session. Within their session they can add and undo traffic entries, view live summaries, and export CSV reports.

## Implementation Details

- Python + Flask handle routing and server logic
- SQLite database with users, sessions, and traffic tables
- Custom SQL queries to manage all data
- Password hashing for secure user accounts
- Session tracking with unique tokens
- Validation of all inputs/requests


## Credits

This project was completed as part of my Software Technologies for Data Science course at the University of Bath. The specification and front-end code was provided by the professor. I implemented the entire backend API and SQLite database.

Let me know if you would like me to modify or expand this README. The goal was to provide a concise overview of the key technical details and outcomes.