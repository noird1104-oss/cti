import os

import psycopg2
from dotenv import load_dotenv

load_dotenv()


def get_url():
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    import streamlit as st  # Streamlit Cloud用(次のフェーズで使います)
    return st.secrets["DATABASE_URL"]


def get_conn():
    return psycopg2.connect(get_url())
