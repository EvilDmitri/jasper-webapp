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
    Route('/', handler='handlers.IndexHandler', name='index'),
    Route('/index', handler='handlers.IndexHandler', name='index'),
    Route('/tradies', handler='handlers.TradiesHandler', name='tradies'),
    Route('/faqs', handler='handlers.FaqsHandler', name='faqs'),
    Route('/jobs', handler='handlers.JobsHandler', name='jobs'),



    #-----------------------------------------------------------
    Route('/', handler='handlers.IndexHandler', name='index'),
    Route('/<result_id>', handler='handlers.IndexResultHandler', name='index_result'),
    Route('/results', handler='handlers.ResultsHandler', name='results'),
    Route('/result/<result_id>', handler='handlers.ShowResultHandler', name='show_result'),
    Route('/all_malls', handler='handlers.AllMallsHandler', name='all_malls'),

    Route('/grab', handler='handlers.GrabHandler', name='grab', methods=['POST']),
    Route('/grabber/daily', handler='handlers.GrabDailyHandler', name='grab_daily', methods=['GET']),

    Route('/logout', handler='handlers.AuthHandler:logout', name='logout'),
    Route('/profile', handler='handlers.ProfileHandler', name='profile'),

    Route('/auth/<provider>',
          handler='handlers.AuthHandler:_simple_auth', name='auth_login'),
    Route('/auth/<provider>/callback',
          handler='handlers.AuthHandler:_auth_callback', name='auth_callback')
]

app = WSGIApplication(routes, config=app_config, debug=True)
