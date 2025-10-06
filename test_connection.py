import psycopg2

try:
    conn = psycopg2.connect(
        database="trio_airbnb",
        user="postgres",
        password="highness",
        host="localhost",
        port="5432"
    )
    print("✅ Connection successful!")
    conn.close()
except Exception as e:
    print(f"❌ Connection failed: {e}")