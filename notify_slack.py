import sys
import time

import requests

from db import get_conn

import os

WEBHOOK = os.environ.get("SLACK_WEBHOOK_URL")
MAX_PER_RUN = 5   # 1回の実行で送る最大件数(通知の連投を防ぐ)


def esc(text):
    # Slackの特殊記号を無害化(記事の文章で @channel などが発動しないように)
    return (str(text or "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def safe_url(url):
    return str(url or "").replace(" ", "%20").replace("|", "%7C").replace(">", "%3E")


def post(text):
    r = requests.post(WEBHOOK, json={"text": text}, timeout=15)
    r.raise_for_status()


def build(row):
    _id, title, url, source, summary, info = row
    info = info if isinstance(info, dict) else {}
    lines = [f"🔴 *重要* <{safe_url(url)}|{esc(title)}>", f"_{esc(source)}_"]
    if summary:
        lines.append(esc(summary))
    if info.get("vuln_summary"):
        lines.append("脆弱性: " + esc(info["vuln_summary"]))
    if info.get("cves"):
        lines.append("CVE: " + ", ".join(esc(c) for c in info["cves"][:5]))
    if info.get("threat_actors"):
        lines.append("脅威アクター: " + ", ".join(esc(a) for a in info["threat_actors"][:5]))
    if info.get("affected_products"):
        lines.append("影響製品: " + " / ".join(esc(p) for p in info["affected_products"][:5]))
    return "\n".join(lines)


if not WEBHOOK:
    print("SLACK_WEBHOOK_URL が設定されていません")
    sys.exit(1)

if "--test" in sys.argv:
    post("✅ CTI通知のテストです。このメッセージが見えれば設定は成功です。")
    print("テスト送信しました")
    sys.exit(0)

conn = get_conn()
cur = conn.cursor()
cur.execute(
    """
    SELECT id, COALESCE(title_ja, title), url, source_name, summary_ja, ai_info
    FROM articles
    WHERE notified_at IS NULL
      AND ai_extracted_at IS NOT NULL
      AND ai_info->>'importance' IN ('high', 'medium')
      AND created_at > NOW() - INTERVAL '1 day'
    ORDER BY id
    LIMIT %s
    """,
    (MAX_PER_RUN,),
)
rows = cur.fetchall()
print(f"通知対象: {len(rows)}件")

sent = 0
for row in rows:
    try:
        post(build(row))
        cur.execute("UPDATE articles SET notified_at = NOW() WHERE id = %s", (row[0],))
        conn.commit()
        sent += 1
        print(f"送信 id={row[0]}")
    except Exception as e:
        conn.rollback()
        print(f"送信失敗 id={row[0]}: {e}")
        break          # 失敗した分は、次回の実行でやり直されます
    time.sleep(1.5)

cur.close()
conn.close()
print(f"完了: {sent}件を通知しました")
