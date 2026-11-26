from db import get_conn
import feedparser
import psycopg2


FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "JPCERT/CC": "https://www.jpcert.or.jp/rss/jpcert.rdf",
    "CISA": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}

conn = get_conn()
cur = conn.cursor()
new_count = 0

for name, url in FEEDS.items():
    feed = feedparser.parse(url)
    for e in feed.entries:
        cur.execute(
            """
            INSERT INTO articles (source_type, source_name, title, url, published, summary)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (url) DO NOTHING
            """,
            ("rss", name, e.get("title"), e.get("link"),
             e.get("published"), e.get("summary")),
        )
        new_count += cur.rowcount

conn.commit()
cur.close()
conn.close()
print(f"新しく保存した記事: {new_count}件")
