import feedparser
from datetime import datetime
from flask import Blueprint, render_template

news_bp = Blueprint('news', __name__, static_folder='../static', template_folder='../templates')

# Dictionary of feeds, add more as required.
FEEDS = {
    'The Hacker News': 'https://feeds.feedburner.com/TheHackersNews',
    'BleepingComputer': 'https://www.bleepingcomputer.com/feed/'
#    'The Register': 'https://www.theregister.com/security/headlines.atom'
}

# Keywords to filter articles, add keyword to shape the feed
KEYWORDS = ['phishing', 'ransomware', 'smishing', 'quishing', 'typosquatting']

def get_articles():
    all_articles = []

    try:
        for source, url in FEEDS.items():
            feed = feedparser.parse(url)
            for entry in feed.entries[:50]:  # Grab a few more to ensure keyword matches
                title = entry.title.lower()
                summary = entry.get('summary', '').lower()



                if any(keyword in title or keyword in summary for keyword in KEYWORDS):
                    article = {
    			'source': source,
    			'title': entry.title,
    			'link': entry.link,
    			'summary': entry.get('summary', ''),
    			'published': datetime(*entry.published_parsed[:6]).strftime('%Y-%m-%d %H:%M') if 'published_parsed' in entry else '',
    			'published_parsed': entry.get('published_parsed', None)
                    }
                    all_articles.append(article)

        # Sort by parsed publish date (datetime), fallback to oldest if missing
        all_articles.sort(
            key=lambda x: datetime(*x['published_parsed'][:6]) if x['published_parsed'] else datetime.min,
            reverse=True
        )

    except Exception as e:
        print(f"Error fetching news feeds: {e}")
        all_articles = []

    return all_articles

@news_bp.route('/news')
def show_news():
    articles = get_articles()
    return render_template('news.html', articles=articles)
