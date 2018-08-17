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
import logging

######################################
#app info for authentication         #
#                                    #
######################################

config = {}
config['webapp2_extras.sessions'] = {
    'secret_key': 'superSecret',
}

myClientId = '377383676562-ajuojjic2q53s3fom0b051epbimb5pde.apps.googleusercontent.com'
myClientSecret = 'm8EIYexNy60_opmlpAzs4m_B'
myClientURL = 'http://localhost:8080'

###############################################################################################
#database structure, relationships are indicated by StructuredProperty property types         #
#                                                                                             #
###############################################################################################

class User(ndb.Model):
    token = ndb.StringProperty(default=None)
    email = ndb.StringProperty(required=True)
    fName = ndb.StringProperty(default=None)

class Monster(ndb.Model):
    monster_name = ndb.StringProperty(required=True)
    attack = ndb.IntegerProperty(default=-1)
    defense = ndb.IntegerProperty(default=-1)
    elder = ndb.BooleanProperty(default=False)

class Hunter(ndb.Model):
    account_email = ndb.StringProperty(required=True)
    hunter_name = ndb.StringProperty(required=True)
    weapon = ndb.StringProperty(default=None)
    armor_set = ndb.StringProperty(default=None)
    target = ndb.StringProperty(default=None)

##############################################################################
#this is a wrapper for all of my handlers that opens and saves the session   #
#basically pulled directly from the documentation                            #
#http://webapp2.readthedocs.io/en/latest/api/webapp2_extras/sessions.html    #
##############################################################################

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

#####################################################################
#the next four handlers are all for authentication, logging in/out  #
#                                                                   #
#####################################################################
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
                'logoutURL': myClientURL +'/logout',
                'token': self.session.get('token')
            }

            path = os.path.join(os.path.dirname(__file__), 'home.html')
            self.response.out.write(template.render(path, home_values))

class login(BaseHandler):
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
            if(not u):
                u = User()
                u.token = self.session.get('token')
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

            self.redirect(googleURL)

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

############################################################################
#Here is the actual REST API data management handler section.              #
#These return weapon/armor set information from the api via the name       #
#supplied by the user.  If the item is not found, the name alone is used   #
#                                                                          #
############################################################################

#this interacts with the MHW api found at https://mhw-db.com
#to retreive weapon information
def getWeapon(weapon):
    query = '''?q={"name":{"$like":"%''' + weapon + '''%"}}'''
    projection = '''&p={"id":"true",%20"name":"true",%20"rarity":"true",%20"attack":"true",%20"sharpness":"true",%20"assets":"true"}'''
    weaponURL = 'https://mhw-db.com/weapons' + query + projection

    result = urlfetch.fetch(url=weaponURL)
    #if no results are found just store the name passed
    #otherwise store/send the entry most similar
    if(result.status_code == 400):
        return weapon
    parsed = json.loads(result.content)
    return json.dumps(parsed[0])

#this interacts with the MHW api found at https://mhw-db.com
#to retreive armor_set information
def getArmorSet(armor_set):
    query = '''?q={"name":{"$like":"%''' + armor_set + '''%"}}'''
    #logging.info(query)
    projection = '''&p={"id":"true",%20"name":"true",%20"rank":"true",%20"bonus":"true"}'''
    #logging.info(projection)
    armorURL = 'https://mhw-db.com/armor/sets' + query + projection
    result = urlfetch.fetch(url=armorURL)
    #logging.info(result.content)
    #if no results are found just store the name passed
    #otherwise store/send the entry most similar
    if(result.status_code == 400):
        return armor_set
    parsed = json.loads(result.content)
    return json.dumps(parsed[0])

##################################################################################
#user specific hunter management                                                 #
#all gets are public, posts are account specific, and deletes are restricted     #
#                                                                                #
##################################################################################

class HunterHandler(BaseHandler):
    def post(self):
        auth_token = self.request.headers['Authorization']
        user = User.query(User.token == auth_token).get()
        if(user):
            hunter_data = json.loads(self.request.body)
            h = Hunter()
            h.account_email = user.email
            h.hunter_name = hunter_data['hunter_name']
            if 'weapon' in hunter_data:
                h.weapon = getWeapon(hunter_data['weapon'])
            if 'armor_set' in hunter_data:
                h.armor_set = getArmorSet(hunter_data['armor_set'])
            if 'target' in hunter_data:
                h.target = hunter_data['target']
            h.put()

            h_dict = h.to_dict()
            h_dict['self'] = h.key.urlsafe()
            self.response.write(json.dumps(h_dict))

        else:
            self.redirect(myClientURL, True)

    def put(self, id=None):
        if(id):
            auth_token = self.request.headers['Authorization']
            user = User.query(User.token == auth_token).get()
            if(user):
                hunter_data = json.loads(self.request.body)
                h = ndb.Key(urlsafe=id).get()
                if(h.account_email == user.email):
                    h.hunter_name = hunter_data['hunter_name']
                    if 'weapon' in hunter_data:
                        h.weapon = getWeapon(hunter_data['weapon'])
                    else:
                        h.weapon = None
                    if 'armor_set' in hunter_data:
                        h.armor_set = hunter_data['armor_set']
                    else:
                        h.armor_set = None
                    if 'target' in hunter_data:
                        h.target = hunter_data['target']
                    else:
                        target = None
                    h.put()

                    h_dict = h.to_dict()
                    h_dict['self'] = h.key.urlsafe()
                    self.response.write(json.dumps(h_dict))
                else:
                    self.response.status = '403 Forbidden'
                    self.response.write("403 Forbidden")
            else:
                self.redirect(myClientURL, True)
        else:
            self.response.status = '404 Not Found'
            self.response.write("404 Not Found")

    def patch(self, id=None):
        if(id):
            auth_token = self.request.headers['Authorization']
            user = User.query(User.token == auth_token).get()
            if(user):
                hunter_data = json.loads(self.request.body)
                h = ndb.Key(urlsafe=id).get()
                if(h.account_email == user.email):
                    if 'hunter_name' in hunter_data:
                        h.hunter_name = hunter_data['hunter_name']
                    if 'weapon' in hunter_data:
                        h.weapon = getWeapon(hunter_data['weapon'])
                    if 'armor_set' in hunter_data:
                        h.armor_set = hunter_data['armor_set']
                    if 'target' in hunter_data:
                        h.target = hunter_data['target']
                    h.put()

                    h_dict = h.to_dict()
                    h_dict['self'] = h.key.urlsafe()
                    self.response.write(json.dumps(h_dict))
                else:
                    self.response.status = '403 Forbidden'
                    self.response.write("403 Forbidden")
            else:
                self.redirect(myClientURL, True)
        else:
            self.response.status = '404 Not Found'
            self.response.write("404 Not Found")

    def get(self, id=None):
        auth_token = self.request.headers['Authorization']
        user = User.query(User.token == auth_token).get()
        if id:
            if(user):
                h = ndb.Key(urlsafe=id).get()
                if(h.account_email == user.email):
                    self.response.write(h)
                else:
                    self.response.status = '403 Forbidden'
                    self.response.write("403 Forbidden")

            else:
                self.redirect(myClientURL, True)
        else:
            if(user):
                all_hunters = []
                hunters = Hunter.query(Hunter.account_email == user.email).fetch()
                for each_hunter in hunters:
                    new_hunter = each_hunter.to_dict();
                    new_hunter['self'] = each_hunter.key.urlsafe()
                    all_hunters.append(new_hunter)
                self.response.write(json.dumps(all_hunters))

            else:
                self.redirect(myClientURL, True)


    def delete(self, id=None):
        auth_token = self.request.headers['Authorization']
        user = User.query(User.token == auth_token).get()
        if(user):
            h = ndb.Key(urlsafe=id).get()
            if(h):
                if(h.account_email == user.email):
                    ndb.Key(urlsafe=id).delete()
                    self.response.write(h)
                else:
                    self.response.status = '403 Forbidden'
                    self.response.write("403 Forbidden")
            else:
                self.response.status = '404 Not Found'
                self.response.write("404 Not Found")
        else:
            self.redirect(myClientURL, True)

##################################################################################
#universal monster management                                                    #
#                                                                                #
##################################################################################

class MonsterHandler(BaseHandler):
    def post(self):
        auth_token = self.request.headers['Authorization']
        user = User.query(User.token == auth_token).get()
        if(user):
            monster_data = json.loads(self.request.body)
            m = Monster()
            m.monster_name = monster_data['name']
            if 'attack' in monster_data:
                m.attack = monster_data['attack']
            if 'defense' in monster_data:
                m.defense = monster_data['defense']
            if 'elder' in monster_data:
                m.elder = monster_data['elder']
            m.put()

            m_dict = m.to_dict()
            m_dict['self'] = m.key.urlsafe()
            self.response.write(json.dumps(m_dict))

        else:
            self.redirect(myClientURL, True)

    def put(self, id=None):
        if(id):
            auth_token = self.request.headers['Authorization']
            user = User.query(User.token == auth_token).get()
            if(user):
                monster_data = json.loads(self.request.body)
                m = ndb.Key(urlsafe=id).get()
                m.monster_name = monster_data['name']
                if 'attack' in monster_data:
                    m.attack = monster_data['attack']
                else:
                    m.attack = None
                if 'defense' in monster_data:
                    m.defense = monster_data['defense']
                else:
                    m.defense = None
                if 'elder' in monster_data:
                    m.elder = monster_data['elder']
                else:
                    m.elder = False
                m.put()

                m_dict = m.to_dict()
                m_dict['self'] = m.key.urlsafe()
                self.response.write(json.dumps(m_dict))

            else:
                self.redirect(myClientURL, True)
        else:
            self.response.status = '404 Not Found'
            self.response.write("404 Not Found")

    def patch(self, id=None):
        if(id):
            auth_token = self.request.headers['Authorization']
            user = User.query(User.token == auth_token).get()
            if(user):
                monster_data = json.loads(self.request.body)
                m = ndb.Key(urlsafe=id).get()
                m.monster_name = monster_data['name']
                if 'attack' in monster_data:
                    m.attack = monster_data['attack']
                if 'defense' in monster_data:
                    m.defense = monster_data['defense']
                if 'elder' in monster_data:
                    m.elder = monster_data['elder']
                m.put()

                m_dict = m.to_dict()
                m_dict['self'] = m.key.urlsafe()
                self.response.write(json.dumps(m_dict))

            else:
                self.redirect(myClientURL, True)
        else:
            self.response.status = '404 Not Found'
            self.response.write("404 Not Found")

    def get(self, id=None):
        auth_token = self.request.headers['Authorization']
        user = User.query(User.token == auth_token).get()
        if id:
            if(user):
                m = ndb.Key(urlsafe=id).get()
                self.response.write(h)

            else:
                self.redirect(myClientURL, True)
        else:
            if(user):
                all_monsters = []
                monsters = Monster.query().fetch()
                for each_monster in monsters:
                    new_monster = each_monster.to_dict();
                    new_monster['self'] = each_monster.key.urlsafe()
                    all_monsters.append(new_monster)
                self.response.write(json.dumps(all_monsters))

            else:
                self.redirect(myClientURL, True)

    def delete(self, id=None):
        auth_token = self.request.headers['Authorization']
        user = User.query(User.token == auth_token).get()
        if(user):
            m = ndb.Key(urlsafe=id).get()
            if(m):
                ndb.Key(urlsafe=id).delete()
                self.response.write(m)
            else:
                self.response.status = '404 Not Found'
                self.response.write("404 Not Found")
        else:
            self.redirect(myClientURL, True)

#monkey patch for patch operation in webapp2 pulled from my last assignments          
allowed_methods = webapp2.WSGIApplication.allowed_methods
new_allowed_methods = allowed_methods.union(('PATCH',))
webapp2.WSGIApplication.allowed_methods = new_allowed_methods

# [START app]
app = webapp2.WSGIApplication([

    ('/', LandingPage),
    ('/user', login),
    ('/home', HomePage),
    ('/logout', logout),
    ('/hunter', HunterHandler),
    ('/hunter/(.*)', HunterHandler),
    ('/monster', MonsterHandler),
    ('/monster/(.*)', MonsterHandler)

], config=config, debug=True)
# [END app]
