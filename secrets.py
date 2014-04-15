# Copy this file into secrets.py and set keys, secrets and scopes.

# This is a session secret key used by webapp2 framework.
# Get 'a random and long string' from here: 
# http://clsc.net/tools/random-string-generator.php
# or execute this from a python shell: import os; os.urandom(64)
import os

ON_DEV = os.environ.get('SERVER_SOFTWARE', '').startswith('Dev')

SESSION_KEY = "6qzv3s4qzg6g4qzgv3s"

# Google APIs
GOOGLE_APP_ID = '634302217031.apps.googleusercontent.com'
GOOGLE_APP_SECRET = 'NDFpPP-81H_8Pq9jQfJmjvcH'
#
# # Facebook auth apis
# if ON_DEV:
#     # Facebook settings for Development
#     FACEBOOK_APP_ID = ''
#     FACEBOOK_APP_SECRET = ''
# else:
#     # Facebook settings for Production
#     FACEBOOK_APP_ID = ''
#     FACEBOOK_APP_SECRET = ''
#
# TWITTER_CONSUMER_KEY = ''
# TWITTER_CONSUMER_SECRET = ''

# config that summarizes the above
AUTH_CONFIG = {
    # OAuth 2.0 providers
    'google': (GOOGLE_APP_ID, GOOGLE_APP_SECRET,
               'https://www.googleapis.com/auth/userinfo.profile'),
    #
    # 'facebook': (FACEBOOK_APP_ID, FACEBOOK_APP_SECRET,
    #               'user_about_me'),
    # # OAuth 1.0 providers don't have scopes
    # 'twitter': (TWITTER_CONSUMER_KEY, TWITTER_CONSUMER_SECRET),

    # OpenID doesn't need any key/secret
}
