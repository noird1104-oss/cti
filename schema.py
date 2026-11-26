from db import get_conn

SQL = """
CREATE TABLE IF NOT EXISTS articles (
    id SERIAL PRIMARY KEY,
    source_type TEXT,
    source_name TEXT,
    title TEXT,
    url TEXT UNIQUE,
    published TEXT,
    summary TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    title_ja TEXT,
    summary_ja TEXT,
    ai_info JSONB,
    ai_extracted_at TIMESTAMP,
    notified_at TIMESTAMP
);
"""

conn = get_conn()
cur = conn.cursor()
cur.execute(SQL)
conn.commit()
cur.close()
conn.close()
print("テーブルを作成しました")
