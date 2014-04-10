import HTMLParser
import urllib, urllib2, Cookie

from google.appengine.api import urlfetch
from google.appengine.ext import ndb
from google.appengine.ext.ndb import Key
from google.appengine.runtime.apiproxy_errors import CapabilityDisabledError
from lxml import html
import re

from models import ResultModel, SitesModel

TAG_RE = re.compile(r'<[^>]+>')
pClnUp = re.compile(r'\n|\t|\xa0|0xc2|\\')


def get_data_from_html(data):
    """Cleans data from tags, special symbols"""
    snippet = urllib.unquote(data)
    h = HTMLParser.HTMLParser()
    snippet = h.unescape(snippet)
    snippet = snippet.encode('utf-8')
    # Clean from tags
    snippet = TAG_RE.sub('', snippet)
    #Clean from command chars
    clean_text = str(pClnUp.sub('', snippet))

    snippet = clean_text[:1000]
    return snippet.decode('utf8', 'ignore')


def site_key(site_name):
    return ndb.Key('SitesModel', site_name)


class URLOpener:
    def __init__(self):
        self.cookie = Cookie.SimpleCookie()

    def open(self, url, data=None):
        if data is None:
            method = urlfetch.GET
        else:
            method = urlfetch.POST

        while url is not None:
            response = urlfetch.fetch(url=url,
                                      payload=data,
                                      method=method,
                                      headers=self._getHeaders(self.cookie),
                                      allow_truncated=False,
                                      follow_redirects=False,
                                      deadline=10
            )
            data = None  # Next request will be a get, so no need to send the data again.
            method = urlfetch.GET
            self.cookie.load(response.headers.get('set-cookie', ''))  # Load the cookies from the response
            url = response.headers.get('location')

        return response

    def _getHeaders(self, cookie):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)',
            'Cookie': self._makeCookieHeader(cookie)
        }
        return headers

    def _makeCookieHeader(self, cookie):
        cookieHeader = ""
        for value in cookie.values():
            cookieHeader += "%s=%s; " % (value.key, value.value)
        return cookieHeader


class Grabber():
    def __init__(self, url):
        self.site_name = unicode(url)

    @staticmethod
    def update_site_results(result_id, site_name):
        try:
            site = SitesModel.query().filter(SitesModel.site_name == site_name)
            site = site.fetch()[0]
            results = '/'.join([str(site.results), str(result_id)])
            site.results = results
            site.put()
        except Exception:
            site = SitesModel(key=site_key(site_name), site_name=site_name, results=result_id)
            site.put()

    def save_result(self, merchants_data):
        """Accept list with strings"""
        merchants = r'\n'.join(x for x in merchants_data)
        result = ResultModel(merchants=merchants, site_name=self.site_name)
        result.put()
        result_id = result.key.id()
        result_id = '|'.join([str(result_id), str(result.timestamp)])
        self.update_site_results(result_id=result_id, site_name=self.site_name)
        return result_id


class XmlGrabber(Grabber):
    URLS = {
        'discover.com': 'https://www.discover.com/credit-cards/cashback-bonus/xml/ShopD_Public_CBB_Partners.xml?',
    }

    def __init__(self, url):
        Grabber.__init__(self, url)
        self.url = self.URLS[url]

    def grab(self):
        opener = URLOpener()
        website = opener.open(self.url)
        # Save page content to string
        page = str(website.content)
        tree = html.fromstring(page)

        merchants_data = []
        lines = tree.xpath('//pd')
        for line in lines:
            title = line.attrib['p']
            cost = ''.join([str(float(line.attrib['cbb']) * 100) + '% Cashback'])

            m = r'\t'.join([title, cost])
            merchants_data.append(m)

        result_id = self.save_result(merchants_data)
        return result_id


class UltimateRewardsGrabber(Grabber):
    URLS = {
        'ultimaterewardsearn.chase.com': 'http://ultimaterewardsearn.chase.com/shopping',
        'aadvantageeshopping.com': 'https://www.aadvantageeshopping.com/shopping/b____alpha.htm',
        'dividendmilesstorefront.com': 'https://www.dividendmilesstorefront.com/shopping/b____alpha.htm',
        'onlinemall.my.bestbuy.com': 'https://onlinemall.my.bestbuy.com/shopping/b____alpha.htm',
        'mileageplusshopping.com': 'https://www.mileageplusshopping.com/shopping/b____alpha.htm',
        'mileageplanshopping.com': 'https://www.mileageplanshopping.com/shopping/b____alpha.htm',
        'rapidrewardsshopping.southwest.com': 'https://rapidrewardsshopping.southwest.com/shopping/b____alpha.htm',
        'barclaycardrewardsboost.com': 'https://www.barclaycardrewardsboost.com/shopping/b____alpha.htm',
        'skymilesshopping.com': 'http://www.skymilesshopping.com/shopping/b____alpha.htm',

    }

    def __init__(self, url):
        Grabber.__init__(self, url)
        self.url = self.URLS[url]

    def grab(self):
        opener = URLOpener()
        website = opener.open(self.url)
        # Save page content to string
        page = str(website.content)
        tree = html.fromstring(page)

        titles = tree.xpath('//div[@class="mn_srchListSection"]/ul/li/a[@rel="external"]')

        costs = tree.xpath('//div[@class="mn_srchListSection"]/ul/li/span')
        merchants = dict(zip(titles, costs))

        merchants_data = []
        for merchant in merchants:
            title = merchant.text

            cost = merchants[merchant].text_content()

            m = r'\t'.join([title, cost])
            merchants_data.append(m)

        result_id = self.save_result(merchants_data)
        return result_id


class ShopGrabber(Grabber):
    URLS = {
        'shop.upromise.com': 'http://shop.upromise.com/mall/view-all-companies'
    }

    def __init__(self, url):
        Grabber.__init__(self, url)
        self.url = self.URLS[url]

    def grab(self):
        opener = URLOpener()
        website = opener.open(self.url)
        # Save page content to string
        page = str(website.content)
        tree = html.fromstring(page)

        titles = tree.xpath('//div[@id="allStores"]/ul/li/a')
        costs = tree.xpath('//div[@id="allStores"]/ul/li')
        merchants = dict(zip(titles, costs))

        merchants_data = []
        for merchant in merchants:
            title = get_data_from_html(merchant.text)
            cost = get_data_from_html(merchant.tail)
            m = r'\t'.join([title, cost])
            merchants_data.append(m)

        result_id = self.save_result(merchants_data)
        return result_id


class RetailersGrabber(Grabber):
    URLS = {
        'shop.amtrakguestrewards.com': 'http://shop.amtrakguestrewards.com/az',
        'shop.lifemiles.com': 'http://shop.lifemiles.com/en/az'
    }

    def __init__(self, url):
        Grabber.__init__(self, url)
        self.url = self.URLS[url]
        self.merchants_data = []

    def grab(self):

        opener = URLOpener()
        website = opener.open(self.url)
        # Save page content to string
        page = str(website.content)
        tree = html.fromstring(page)

        data = tree.xpath('//div[@class="merch-full"]/a')
        for merch in data:
            title = get_data_from_html(merch[1].text)
            cost = get_data_from_html(merch[2].text)
            m = r'\t'.join([title, cost])
            self.merchants_data.append(m)

        try:
            next_page = tree.xpath('//div[@class="paging"]/ul/li[@class="ne"]/a')[0]
            self.url = 'http://shop.amtrakguestrewards.com/' + next_page.values()[0]
            self.grab()
        except IndexError:
            result_id = self.save_result(self.merchants_data)
            return result_id


class BestbuyGrabber(Grabber):
    post = {'id': 'pcat17096', 'type': 'page', 'rd': '248', 's': '10001',
            'nrp': '150',
            'ld': '40.75080490112305', 'lg': '-73.99664306640625'
            }

    URLS = {
        'www.bestbuy.com': 'http://www.bestbuy.com/site/olstemplatemapper.jsp?'
    }

    def __init__(self, url):
        Grabber.__init__(self, url)
        self.url = self.URLS[url]
        self.data = []

    def handle_result(self, rpc):
        result = rpc.get_result()

        # Save page content to string
        page = str(result.content)
        tree = html.fromstring(page)

        divs = tree.xpath('//div[@class="info-main"]')

        for div in divs:
            name = div.xpath('h3')[0].text_content()
            if u'Apple' in name or u'apple' in name:
                try:
                    model = get_data_from_html(
                        div.xpath('div[@class="attributes"]/h5/strong[@itemprop="model"]')[0].text_content())
                except IndexError:
                    model = ''

                try:
                    sku = get_data_from_html(
                        div.xpath('div[@class="attributes"]/h5/strong[@class="sku"]')[0].text_content())
                except IndexError:
                    sku = ''

                try:
                    condition = get_data_from_html(
                        div.xpath('div[@class="attributes"]/h5/a/strong[@class="sku"]')[0].text_content())
                except IndexError:
                    condition = ''

                try:
                    quantity = get_data_from_html(div.xpath('div[@class="availHolder"]/p/strong')[0].text_content())
                except IndexError:
                    quantity = ''

                try:
                    location = get_data_from_html(div.xpath('div[@class="availHolder"]/strong')[0].text_content())
                except IndexError:
                    location = ''

                data_line = r'\t'.join([
                    name.rstrip().lstrip(), model.rstrip().lstrip(),
                    sku.rstrip().lstrip(), condition.rstrip().lstrip(),
                    quantity.rstrip().lstrip(), location.rstrip().lstrip()
                ])
                print data_line.encode('utf-8', 'ignore')
                self.data.append(data_line)

    # Use a helper function to define the scope of the callback.
    def create_callback(self, rpc):
        return lambda: self.handle_result(rpc)

    def grab(self):
        self.post['cp'] = 1
        form_data = urllib.urlencode(self.post)
        website = urlfetch.fetch(url=self.url,
                                 payload=form_data,
                                 method=urlfetch.POST,
                                 headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )

        # Get the number of pages
        page = str(website.content)
        tree = html.fromstring(page)
        pages = tree.xpath('//div[@id="showing"]')[0].text_content()
        pages_count = int(pages.split('\n')[-1]) / 50 + 1

        rpcs = []
        for page_number in range(1, 50):
            rpc = urlfetch.create_rpc()
            rpc.callback = self.create_callback(rpc)

            self.post['cp'] = page_number
            form_data = urllib.urlencode(self.post)
            website = urlfetch.make_fetch_call(rpc=rpc,
                                               url=self.url,
                                               payload=form_data,
                                               method=urlfetch.POST,
                                               headers={'Content-Type': 'application/x-www-form-urlencoded'}
                                               )
            rpcs.append(rpc)
        for rpc in rpcs:
            rpc.wait()

        result_id = self.save_result(self.data)
        return result_id


if __name__ == '__main__':
    grabber = BestbuyGrabber('bestbuy.com')
    grabber.grab()
