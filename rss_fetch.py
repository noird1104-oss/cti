import feedparser

FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "JPCERT/CC": "https://www.jpcert.or.jp/rss/jpcert.rdf",
    "CISA": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
}

for name, url in FEEDS.items():
    feed = feedparser.parse(url)
    print(f"\n=== {name}: {len(feed.entries)}件 ===")
    for e in feed.entries[:5]:
        print("-", e.get("title"))
        print("  ", e.get("link"))
        print("  ", e.get("published", "日付なし"))
