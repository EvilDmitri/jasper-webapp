# -*- coding: utf-8 -*-

from collections import OrderedDict

import os
import datetime

from google.appengine.ext import ndb
from google.appengine.runtime.apiproxy_errors import CapabilityDisabledError
from config import URLS
from grabber.scrape import get_data_from_html, XmlGrabber, BestbuyGrabber, RetailersGrabber, ShopGrabber, \
    UltimateRewardsGrabber
from models import ResultModel, SitesModel
import secrets
import logging

import webapp2
import jinja2
from webapp2_extras import auth, sessions
from webapp2_extras import jinja2 as jinja

from jinja2.runtime import TemplateNotFound

from simpleauth import SimpleAuthHandler

jinja_environment = jinja2.Environment(autoescape=True,
                                       loader=jinja2.FileSystemLoader(os.path.join(os.path.dirname(__file__),
                                       'server')))


class BaseRequestHandler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)

    @webapp2.cached_property
    def jinja2(self):
        """Returns a Jinja2 renderer cached in the app registry"""
        return jinja.get_jinja2(app=self.app)

    @webapp2.cached_property
    def session(self):
        """Returns a session using the default cookie key"""
        return self.session_store.get_session()

    @webapp2.cached_property
    def auth(self):
        return auth.get_auth()

    @webapp2.cached_property
    def current_user(self):
        """Returns currently logged in user"""
        user_dict = self.auth.get_user_by_session()
        return self.auth.store.user_model.get_by_id(user_dict['user_id'])

    @webapp2.cached_property
    def logged_in(self):
        """Returns true if a user is currently logged in, false otherwise"""
        return self.auth.get_user_by_session() is not None

    def render(self, template_name, template_vars={}):
        # Preset values for the template
        values = {
            'url_for': self.uri_for,
            'logged_in': self.logged_in,
            'flashes': self.session.get_flashes()
        }

        # Add manually supplied template values
        values.update(template_vars)

        # read the template or 404.html
        template = jinja_environment.get_template(template_name)
        try:
            self.response.write(self.jinja2.render_template(template, **values))
        except TemplateNotFound:
            self.abort(404)

    def head(self, *args):
        """Head is used by Twitter. If not there the tweet button shows 0"""
        pass


class RootHandler(BaseRequestHandler):
    def get(self):
        """Handles default landing page"""
        self.render('home.html')


class ProfileHandler(BaseRequestHandler):
    def get(self):
        """Handles GET /profile"""
        if self.logged_in:
            self.render('profile.html', {
                'user': self.current_user,
                'session': self.auth.get_user_by_session()
            })
        else:
            self.redirect('/')


class LoginHandler(BaseRequestHandler):
    def get(self):
        """Handles GET /profile"""
        if self.logged_in:
            name = self.current_user.name.encode('utf8')
            if name == 'Дмитрий Брач' or name == 'Jasper Moy':
                self.redirect('/admin')
            else:
                self.redirect('/logout')
                return
        else:
            self.render('login.html', {})


class ResultsHandler(BaseRequestHandler):
    def get(self):
        """Handles GET /index and /"""
        results = ResultModel.query().order(-ResultModel.timestamp).fetch()
        values = {
                  'site_names': URLS,
                  'results': results
                  }
        # self.session.add_flash('Some message', level='error')
        self.render('list_data.html', values)



class DeleteResultHandler(BaseRequestHandler):
    def post(self, result_id):
        """Delete a results object"""
        if self.logged_in:
            result = ResultModel.get_by_id(int(result_id))

            # Should delete result from site model
            site = result.site_name
            print site
            q = "SELECT * FROM SitesModel  WHERE site_name = '%s'" % site
            data_entry = ndb.gql(q).fetch()[0]
            print data_entry
            results = data_entry.results.split('/')
            for result in results:
                if str(result_id) in result:
                    results.remove(result)
            data_entry.results = '/'.join(results)
            data_entry.put()

            try:
                result.key.delete()
                self.session.add_flash(u'result %s successfully deleted.' % result_id, level='success')
            except CapabilityDisabledError:
                self.session.add_flash(u'App Engine Datastore is currently in read-only mode.', level='error')
            return self.redirect('/results')
        else:
            self.redirect('/login')


class IndexHandler(BaseRequestHandler):
    def get(self):
        """Handles GET /index and /"""
        results = ResultModel.query().order(-ResultModel.timestamp).fetch()
        values = {
                  'site_names': URLS,
                  'results': results
                  }
        # self.session.add_flash('Some message', level='error')
        self.render('index.html', values)



class IndexResultHandler(BaseRequestHandler):
    def get(self, result_id):
        """Handles """
        result = ResultModel.get_by_id(int(result_id))

        date = result.timestamp

        data = []
        site = result.site_name
        result = result.merchants
        lines = result.split(r'\n')
        for line in lines:
            items = line.split(r'\t')
            if len(items) == 6:
                site = 'apple'      # This is needed for 'www.bestbuy.com'
            data.append(items)

        results = ResultModel.query().order(-ResultModel.timestamp).fetch()
        values = {
                  'site_names': URLS,
                  'results': results,
                  'merchants': data,
                  'date': date,
                  'site': site
                  }
        # self.session.add_flash('Some message', level='error')
        self.render('index.html', values)


class AdminHandler(BaseRequestHandler):
    def get(self):
        """Page to delete some results"""
        if self.logged_in:
            name = self.current_user.name.encode('utf8')
            if name == 'Дмитрий Брач' or name == 'Jasper Moy':
                results = ResultModel.query().order(-ResultModel.timestamp).fetch()
                values = {'user': self.current_user,
                          'site_names': URLS,
                          'results': results
                          }
                # self.session.add_flash('Some message', level='error')
                self.render('admin.html', values)
            else:
                self.redirect('/logout')
                return

        else:
            self.redirect('/login')

class AllMallsHandler(BaseRequestHandler):
    def get(self):
        """Response all malls from last job"""
        start_time = datetime.datetime.now()

        date = start_time.strftime('%Y-%m-%d %H:%M:%S')

        results = ResultModel.query().order(-ResultModel.timestamp).fetch()
        last_results = results[-10:]
        data_entries = last_results

        sites = OrderedDict([[x, '-'] for x in URLS])
        headers = OrderedDict([[x, '-'] for x in URLS])
        data = dict()
        for entry in data_entries:
            date_scraped = entry.timestamp
            scraped_from = entry.site_name
            # Table header
            headers[scraped_from] = ('\n'.join([scraped_from, date_scraped.strftime('%Y-%m-%d %H:%M:%S')]))

            vendors = entry.merchants
            vendors = vendors.split(r'\n')

            for vendor in vendors:
                result = vendor.split(r'\t')

                name = result[0]
                try:
                    rate = result[1]
                except ValueError:
                    rate = ' '

                try:    # If this vendor is listed
                    rates = data[name]
                except KeyError:
                    rates = sites
                rates[scraped_from] = rate

                data[name] = rates

        # for item in data:
        #     print item
        #     print '----------'
        #     costs = data[item]
        #     for d in costs:
        #         cost = get_data_from_html(costs[d])
        #         if cost == u' ':
        #             pass
        #         else:
        #             print d, cost
        # print '==================='
        # print headers
        values = {
                  'site_names': URLS,
                  'date': date,
                  'data': data,
                  'site': ''
                  }
        return self.render('all_malls.html', values)


#------------------------------------------
# Method run grabber from web-page
#------------------------------------------
class GrabHandler(BaseRequestHandler):
    def post(self):
        site_name = self.request.get('site_name')
        print site_name

        if 'discover.com' in site_name:
            grabber = XmlGrabber(site_name)
        elif 'shop.upromise.com' in site_name:
            grabber = ShopGrabber(site_name)
        elif 'www.bestbuy.com' in site_name:
            grabber = BestbuyGrabber(site_name)
        elif site_name in ['shop.amtrakguestrewards.com', 'shop.lifemiles.com']:
            grabber = RetailersGrabber(site_name)
        else:
            grabber = UltimateRewardsGrabber(site_name)

        result_id = grabber.grab()
        self.session.add_flash(u'Successfully grabbed', level='success')
        return result_id


#------------------------------------------
# Method run grabber from web-page
#------------------------------------------
class GrabDailyHandler(BaseRequestHandler):
    def get(self):
        success = 0
        for site_name in URLS:
            if 'discover.com' in site_name:
                grabber = XmlGrabber(site_name)
            elif 'shop.upromise.com' in site_name:
                grabber = ShopGrabber(site_name)

            elif site_name in ['shop.amtrakguestrewards.com', 'shop.lifemiles.com']:
                grabber = RetailersGrabber(site_name)
            # elif 'www.bestbuy.com' in site_name:
            #     grabber = BestbuyGrabber(site_name)
            else:
                grabber = UltimateRewardsGrabber(site_name)

            if grabber.grab():
                success += 1

        # Now it's time to check if data is changed since last scrape and if so post an email

        checker = CheckModificationHandler()
        checker.get()
        return 'OK'


#------------------------------------------
# Method for check last result with previous
#------------------------------------------
class CheckModificationHandler(BaseRequestHandler):
    def get_data(self, result_id):
        """Get data from DB by id
        Return dictionary with 'name': 'rate'
        """
        result = ResultModel.get_by_id(int(result_id))
        try:
            result = result.merchants
        except AttributeError:
            return False

        data = result.split(r'\n')
        merchants = dict()
        for item in data:
            res = item.split(r'\t')
            name = res[0]
            rate = res[1].split(' ')[0]
            merchants[name] = rate
        return merchants

    def compare_data(self, last, prev):
        """Receive two dictionary with 'name': 'rate'
        If some of them is changed should alert?
        """
        list_of_changes = []
        for name in last:
            last_rate = last[name]
            try:
                prev_rate = prev[name]
                if last_rate != prev_rate:
                    changed = name + ' ' + prev_rate + '/' + last_rate
                    list_of_changes.append(changed)
            except KeyError:
                changed = name + ' ' + ' ' + '/' + last_rate
                list_of_changes.append(changed)

        return list_of_changes

    def get(self):
        if self.logged_in:
            sites = SitesModel.query().order().fetch()
            changed_sites = OrderedDict([[x, ' '] for x in URLS])
            for site in sites:
                results = site.results
                lasts = results.split('/')
                if len(lasts) < 2:
                    # Only one result
                    continue

                last = lasts[-1].split('|')[0]  # [1] - timestamp
                last_result = self.get_data(last)

                i = -2
                while True:
                    prev = lasts[i].split('|')[0]
                    prev_result = self.get_data(prev)
                    if prev_result:
                        break
                    i -= 1
                # Now we have IDs

                changes = self.compare_data(last_result, prev_result)
                if len(changes) > 0:
                    changed_sites[site.site_name] = changes

            # Mail results
            from mailer.mail_send import SendStatistics
            stat = False
            for val in changed_sites.itervalues():
                if val is not ' ':
                    stat = True
                    break

            if stat:
                result = ''
                for k in changed_sites.iterkeys():
                    changes = changed_sites[k]
                    changed_cost = ''
                    for change in changes:
                        change = ' '.join(get_data_from_html(change).split('/$'))
                        if change:
                            changed_cost = '; '.join([change, changed_cost])
                    if changed_cost:
                        line = ' '.join([k, changed_cost])
                        result = '\n'.join([result, line])

                stats = SendStatistics()
                stats.post(data=result)
            values = {'user': self.current_user,
                      'site_names': URLS,
                      'sites': changed_sites,
                      'site': ''
                      }
            # self.session.add_flash('Some message', level='error')
            self.render('index.html', values)
        else:
            self.redirect('/login')


#------------------------------------------
class SearchResultByTimeHandler(BaseRequestHandler):
    def post(self):
        time = self.request.form['time']
        date = self.request.form['date']
        try:
            end_date = datetime.datetime.strptime(date + ' 00:00', '%m/%d/%Y %H:%M')
            start_date = end_date + datetime.timedelta(days=1)
            q = "SELECT * FROM ResultModel WHERE timestamp <= DATETIME('%s') AND timestamp >= DATETIME('%s')" % (start_date, end_date)
            results = ndb.gql(q).fetch()
        except ValueError:
            results = ''

        data = []
        for result in results:
            timestamp = result.timestamp.strftime('%b %d, %Y %I:%M %p')
            if time in timestamp:
                data.append(result)
        values = {'site_names': URLS,
                  'results': data
                  }
        # self.session.add_flash('Some message', level='error')
        self.render('list_data.html', values)


class AuthHandler(BaseRequestHandler, SimpleAuthHandler):
    """Authentication handler for OAuth 2.0, 1.0(a) and OpenID."""

    # Enable optional OAuth 2.0 CSRF guard
    OAUTH2_CSRF_STATE = True

    @webapp2.cached_property
    def session(self):
        """Returns a session using the default cookie key"""
        return self.session_store.get_session()

    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)
        try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
        finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)

    USER_ATTRS = {
        'facebook': {
            'id': lambda id: ('avatar_url',
                              'http://graph.facebook.com/{0}/picture?type=large'.format(id)),
            'name': 'name',
            'link': 'link'
        },
        'google': {
            'picture': 'avatar_url',
            'name': 'name',
            'profile': 'link'
        },
        'windows_live': {
            'avatar_url': 'avatar_url',
            'name': 'name',
            'link': 'link'
        },
        'twitter': {
            'profile_image_url': 'avatar_url',
            'screen_name': 'name',
            'link': 'link'
        },
        'linkedin': {
            'picture-url': 'avatar_url',
            'first-name': 'name',
            'public-profile-url': 'link'
        },
        'linkedin2': {
            'picture-url': 'avatar_url',
            'first-name': 'name',
            'public-profile-url': 'link'
        },
        'foursquare': {
            'photo': lambda photo: ('avatar_url', photo.get('prefix') + '100x100' + photo.get('suffix')),
            'firstName': 'firstName',
            'lastName': 'lastName',
            'contact': lambda contact: ('email', contact.get('email')),
            'id': lambda id: ('link', 'http://foursquare.com/user/{0}'.format(id))
        },
        'openid': {
            'id': lambda id: ('avatar_url', '/img/missing-avatar.png'),
            'nickname': 'name',
            'email': 'link'
        }
    }

    def _on_signin(self, data, auth_info, provider):
        """Callback whenever a new or existing user is logging in.
     data is a user info dictionary.
     auth_info contains access token or oauth token and secret.
    """
        auth_id = '%s:%s' % (provider, data['id'])
        logging.info('Looking for a user with id %s', auth_id)

        user = self.auth.store.user_model.get_by_auth_id(auth_id)
        _attrs = self._to_user_model_attrs(data, self.USER_ATTRS[provider])

        if user:
            logging.info('Found existing user to log in')
            # Existing users might've changed their profile data so we update our
            # local model anyway. This might result in quite inefficient usage
            # of the Datastore, but we do this anyway for demo purposes.
            #
            # In a real app you could compare _attrs with user's properties fetched
            # from the datastore and update local user in case something's changed.
            user.populate(**_attrs)
            user.put()
            self.auth.set_session(
                self.auth.store.user_to_dict(user))

        else:
            # check whether there's a user currently logged in
            # then, create a new user if nobody's signed in,
            # otherwise add this auth_id to currently logged in user.

            if self.logged_in:
                logging.info('Updating currently logged in user')

                u = self.current_user
                u.populate(**_attrs)
                # The following will also do u.put(). Though, in a real app
                # you might want to check the result, which is
                # (boolean, info) tuple where boolean == True indicates success
                # See webapp2_extras.appengine.auth.models.User for details.
                u.add_auth_id(auth_id)

            else:
                logging.info('Creating a brand new user')
                ok, user = self.auth.store.user_model.create_user(auth_id, **_attrs)
                if ok:
                    self.auth.set_session(self.auth.store.user_to_dict(user))

        # Remember auth data during redirect, just for this demo. You wouldn't
        # normally do this.
        # self.session.add_flash(data, 'data - from _on_signin(...)')
        # self.session.add_flash(auth_info, 'auth_info - from _on_signin(...)')

        # Go to the jobs page
        self.redirect('/login')

    def logout(self):
        self.auth.unset_session()
        self.redirect('/results')

    def handle_exception(self, exception, debug):
        logging.error(exception)
        self.render('error.html', {'exception': exception})

    def _callback_uri_for(self, provider):
        return self.uri_for('auth_callback', provider=provider, _full=True)

    def _get_consumer_info_for(self, provider):
        """Returns a tuple (key, secret) for auth init requests."""
        return secrets.AUTH_CONFIG[provider]

    def _to_user_model_attrs(self, data, attrs_map):
        """Get the needed information from the provider dataset."""
        user_attrs = {}
        for k, v in attrs_map.iteritems():
            attr = (v, data.get(k)) if isinstance(v, str) else v(data.get(k))
            user_attrs.setdefault(*attr)

        return user_attrs
