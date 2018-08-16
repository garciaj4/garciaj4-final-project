from google.appengine.api import users
from google.appengine.ext import ndb
from google.appengine.ext.webapp import template
from google.appengine.api import urlfetch
import webapp2
import json
import os
import base64
import uuid
from webapp2_extras import sessions
import urllib

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'superSecret',
}

myClientId = '377383676562-ajuojjic2q53s3fom0b051epbimb5pde.apps.googleusercontent.com'
myClientSecret = 'm8EIYexNy60_opmlpAzs4m_B'
myClientURL = 'http://localhost:8080'

class User(ndb.Model):
    token = ndb.StringProperty(default=None)
    email = ndb.StringProperty(required=True)
    fName = ndb.StringProperty(default=None)

#this is a wrapper for all of my handlers that opens and saves the session
#basically pulled directly from the documentation
#http://webapp2.readthedocs.io/en/latest/api/webapp2_extras/sessions.html
class BaseHandler(webapp2.RequestHandler):
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
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()

class LandingPage(BaseHandler):
    def get(self):
        landing_values = {
            'redirectURL': myClientURL + '/user'
        }

        path = os.path.join(os.path.dirname(__file__), 'landing.html')
        self.response.out.write(template.render(path, landing_values))

class HomePage(BaseHandler):
    def get(self):

        user = User.query(User.email == self.session.get('email') and User.token == self.session.get('token')).get()
        #self.response.write(user)
        if(user):
            name = user.fName or user.email

            home_values = {
                'fName': name,
                'logoutURL': myClientURL +'/logout'
            }

            path = os.path.join(os.path.dirname(__file__), 'home.html')
            self.response.out.write(template.render(path, home_values))

class user(BaseHandler):
    def get(self):
        #if we already have a token stored
        #make a request to google+ api with token and store email/token
        if(self.session.get('token')):

            #build an http get request to get the users data
            googleDataURL = 'https://www.googleapis.com/plus/v1/people/me'
            token = 'Bearer ' + self.session.get('token')
            headers = {'authorization': token}
            result = urlfetch.fetch(url=googleDataURL, headers=headers)

            #self.response.write(result.content)
            
            result_data = json.loads(result.content)

            self.session['email'] = result_data['emails'][0]['value']

            u = User.query(User.email == self.session.get('email')).get()
            if(u):
                u.token = self.session.get('token')
                u.put()
            else:
                u = User()
                u.fName = result_data['name']['givenName']
                u.email = self.session.get('email')
                u.token = self.session.get('token')
                u.put()

            #all_users = User.query().fetch()
            #self.response.write(all_users)
            self.redirect(myClientURL + '/home')

        elif(self.request.get('state')):
            if(self.session.get('state') == self.request.get('state')):
                googleURL = 'https://www.googleapis.com/oauth2/v4/token'
                payload = urllib.urlencode({
                    'code':self.request.get('code'),
                    'client_id': myClientId,
                    'client_secret': myClientSecret,
                    'redirect_uri': myClientURL + '/user',
                    'grant_type': 'authorization_code'
                })

                result = urlfetch.fetch(googleURL, method=urlfetch.POST, payload=payload)
                result_data = json.loads(result.content)

                self.session['token'] = result_data['access_token']

                self.redirect(myClientURL + '/user')
                #self.response.write(result_data)
            else:
                self.response.write('Invalid State Returned')

        else:
            myState = base64.urlsafe_b64encode(uuid.uuid4().bytes)
            myState = myState.replace('=', '')

            self.session['state'] = myState

            googleURL = 'https://accounts.google.com/o/oauth2/v2/auth'
            googleURL += '?response_type=code'
            googleURL += '&client_id=' + myClientId
            googleURL += '&redirect_uri=' + myClientURL + '/user'
            googleURL += '&scope=email'
            googleURL += '&state=' + myState

            self.redirect(googleURL, 302)

class logout(BaseHandler):
    def get(self):
        email = self.session.get('email')
        self.response.write(email)
        token = self.session.get('token')
        self.response.write(token)
        u = User.query(User.email == email and User.token == token).get()
        self.response.write(u)
        if(u):
            self.session['email'] = None
            self.session['token'] = None
            u.token = None
            u.put()

        self.redirect(myClientURL)

# [START app]
app = webapp2.WSGIApplication([

    ('/', LandingPage),
    ('/user', user),
    ('/home', HomePage),
    ('/logout', logout)

], config=config, debug=True)
# [END app]
