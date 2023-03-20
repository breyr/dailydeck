import finnhub
import pandas as pd
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()
API_KEY = os.getenv("FINNHUB_API_KEY")

finnhub_client = finnhub.Client(api_key=API_KEY)

def company_info(company: str):
    """
    return a dict of basic company information
    """
    return finnhub_client.company_profile2(symbol=company)


def company_news(company: str):
    """
    return a dataframe of top 5 most recent news articles referring to company
    """
    _from = datetime.today() - timedelta(weeks=1)
    _from = _from.strftime('%Y-%m-%d')
    to = datetime.today().strftime('%Y-%m-%d')
    news = finnhub_client.company_news(company, _from=_from, to=to)
    return news


def stock_quote(company: str):
    """
    Get real-time quote data for US stocks.
    
    return dict
    """
    return finnhub_client.quote(company)
