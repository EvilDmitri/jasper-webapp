# -*- coding: utf-8 -*-
import sys
from secrets import SESSION_KEY

from webapp2 import WSGIApplication, Route

# inject './lib' dir in the path so that we can simply do "import ndb" 
# or whatever there's in the app lib dir.
if 'lib' not in sys.path:
    sys.path[0:0] = ['lib']

# webapp2 config
app_config = {
    'webapp2_extras.sessions': {
        'cookie_name': '_simpleauth_sess',
        'secret_key': SESSION_KEY
    },
    'webapp2_extras.auth': {
        'user_attributes': []
    }
}

# Map URLs to handlers
routes = [
    Route(r'/', handler='handlers.IndexHandler',
          name='index'),
    Route(r'/<result_id:\d+>', handler='handlers.IndexResultHandler',
          name='index_result'),
    Route(r'/results', handler='handlers.ResultsHandler',
          name='results'),

    Route(r'/delete/<result_id:\d+>', handler='handlers.DeleteResultHandler',
          name='delete_result', methods=['GET', 'POST']),
    Route(r'/all_malls', handler='handlers.AllMallsHandler',
          name='all_malls'),

    Route(r'/grab', handler='handlers.GrabHandler',
          name='grab', methods=['POST']),
    Route(r'/grabber/daily', handler='handlers.GrabDailyHandler',
          name='grab_daily', methods=['GET']),

    Route(r'/compare', handler='handlers.CheckModificationHandler',
          name='search', methods=['GET', 'POST']),
    Route(r'/search', handler='handlers.SearchHandler',
          name='search', methods=['GET', 'POST']),

    Route('/login', handler='handlers.LoginHandler',
          name='login'),
    Route(r'/logout', handler='handlers.AuthHandler:logout',
          name='logout'),
    Route(r'/profile', handler='handlers.ProfileHandler',
          name='profile'),
    Route(r'/auth/<provider>',
          handler='handlers.AuthHandler:_simple_auth', name='auth_login'),
    Route(r'/auth/<provider>/callback',
          handler='handlers.AuthHandler:_auth_callback', name='auth_callback'),

    Route('/admin', handler='handlers.AdminHandler',
          name='admin'),
]

app = WSGIApplication(routes, config=app_config, debug=True)
