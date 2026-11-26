from db import get_conn
import json

import pandas as pd
import psycopg2
import streamlit as st


st.set_page_config(page_title="脅威インテリジェンス", layout="wide")
st.title("インテリジェンス")


@st.cache_data(ttl=60)
def load_articles():
    conn = get_conn()
    df = pd.read_sql(
        "SELECT id, source_name, title, title_ja, url, published, "
        "summary, summary_ja, ai_info, created_at "
        "FROM articles ORDER BY created_at DESC, id DESC",
        conn,
    )
    conn.close()
    return df


df = load_articles()
df["info"] = df["ai_info"].apply(lambda x: x if isinstance(x, dict) else {})
df["cves"] = df["info"].apply(lambda d: d.get("cves", []))
df["actors"] = df["info"].apply(lambda d: d.get("threat_actors", []))
df["importance"] = df["info"].apply(lambda d: d.get("importance", ""))
df["info_text"] = df["info"].apply(lambda d: json.dumps(d, ensure_ascii=False))

c1, c2, c3, c4 = st.columns(4)
c1.metric("保存済み記事", len(df))
c2.metric("重要(high)", int((df["importance"] == "high").sum()))
c3.metric("CVEを含む記事", int((df["cves"].str.len() > 0).sum()))
c4.metric("AI抽出済み", f"{df['ai_info'].notna().mean() * 100:.0f}%" if len(df) else "0%")

left, mid, right = st.columns([3, 1, 1])
keyword = left.text_input("キーワード検索(タイトル・要約・CVE・アクター・IOC)")
only_high = mid.checkbox("重要(high)のみ")
sources = ["すべて"] + sorted(df["source_name"].dropna().unique().tolist())
selected = right.selectbox("情報源", sources)

filtered = df
if selected != "すべて":
    filtered = filtered[filtered["source_name"] == selected]
if only_high:
    filtered = filtered[filtered["importance"] == "high"]
if keyword:
    mask = False
    for col in ["title", "title_ja", "summary", "summary_ja", "info_text"]:
        mask = mask | filtered[col].str.contains(keyword, case=False, na=False)
    filtered = filtered[mask]

st.caption(f"{len(filtered)}件を表示中")

LABEL = {"high": "🔴重要", "medium": "🟡注意", "low": ""}

for _, row in filtered.head(50).iterrows():
    info = row["info"]
    with st.container(border=True):
        title = row["title_ja"] if pd.notna(row["title_ja"]) else row["title"]
        badge = LABEL.get(row["importance"], "")
        st.markdown(f"{badge} **[{title}]({row['url']})**")
        st.caption(f"{row['source_name']} ・ {row['published']}")
        if pd.notna(row["summary_ja"]):
            st.write(row["summary_ja"])
        if info.get("vuln_summary"):
            st.info("脆弱性概要: " + info["vuln_summary"])
        if info.get("cves"):
            scores = {c["cve"]: c["score"] for c in info.get("cvss", [])}
            st.markdown("CVE: " + " ".join(
                f"`{c}`" + (f"(CVSS {scores[c]})" if c in scores else "")
                for c in info["cves"]))
        if info.get("threat_actors"):
            st.markdown("脅威アクター: " + " ".join(f"`{a}`" for a in info["threat_actors"]))
        if info.get("malware"):
            st.markdown("マルウェア: " + " ".join(f"`{m}`" for m in info["malware"]))
        if info.get("affected_products"):
            st.markdown("影響製品: " + " / ".join(info["affected_products"]))
        iocs = info.get("iocs", {})
        if any(iocs.get(k) for k in ["ips", "domains", "urls", "hashes"]):
            with st.expander("IOC"):
                for k, name in [("ips", "IP"), ("domains", "ドメイン"),
                                ("urls", "URL"), ("hashes", "ハッシュ")]:
                    if iocs.get(k):
                        st.markdown(f"**{name}**")
                        st.code("\n".join(iocs[k]), language=None)
