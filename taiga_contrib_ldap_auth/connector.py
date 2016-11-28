# Copyright (C) 2014 Andrey Antukh <niwi@niwi.be>
# Copyright (C) 2014 Jesús Espino <jespinog@gmail.com>
# Copyright (C) 2014 David Barragán <bameda@dbarragan.com>
# Copyright (C) 2015 Ensky Lin <enskylin@gmail.com>
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ldap3 import Server, Connection, SIMPLE, ANONYMOUS, SYNC, ASYNC, SUBTREE, NONE

from django.conf import settings
from taiga.base.connectors.exceptions import ConnectorBaseException


class LDAPLoginError(ConnectorBaseException):
    pass


SERVER = getattr(settings, "LDAP_SERVER", "")
PORT = getattr(settings, "LDAP_PORT", "")

SEARCH_BASE = getattr(settings, "LDAP_SEARCH_BASE", "")
SEARCH_PROPERTY = getattr(settings, "LDAP_SEARCH_PROPERTY", "")
SEARCH_SUFFIX = getattr(settings, "LDAP_SEARCH_SUFFIX", "")
SEARCH_FILTER = getattr(settings, "LDAP_SEARCH_FILTER", "")
BIND_DN = getattr(settings, "LDAP_BIND_DN", "")
BIND_PASSWORD = getattr(settings, "LDAP_BIND_PASSWORD", "")

EMAIL_PROPERTY = getattr(settings, "LDAP_EMAIL_PROPERTY", "")
FULL_NAME_PROPERTY = getattr(settings, "LDAP_FULL_NAME_PROPERTY", "")

def login(username: str, password: str) -> tuple:

    try:
        if SERVER.lower().startswith("ldaps://"):
            server = Server(SERVER, port = PORT, get_info = NONE, use_ssl = True) 
        else:
            server = Server(SERVER, port = PORT, get_info = NONE, use_ssl = False)  # define an unsecure LDAP server, requesting info on DSE and schema

        c = None

        if BIND_DN is not None and BIND_DN != '':
            c = Connection(server, auto_bind = True, client_strategy = SYNC, user=BIND_DN, password=BIND_PASSWORD, authentication=SIMPLE, check_names=True)
        else:
            c = Connection(server, auto_bind = True, client_strategy = SYNC, user=None, password=None, authentication=ANONYMOUS, check_names=True)

    except Exception as e:
        error = "Error connecting to LDAP server: %s" % e
        raise LDAPLoginError({"error_message": error})

    try:
        if(SEARCH_SUFFIX is not None and SEARCH_SUFFIX != ''):
            search_filter = '(%s=%s)' % (SEARCH_PROPERTY, username + SEARCH_SUFFIX)
        else:
            search_filter = '(%s=%s)' % (SEARCH_PROPERTY, username)
        if SEARCH_FILTER:
            search_filter = '(&%s(%s))' % (search_filter, SEARCH_FILTER)
        c.search(search_base = SEARCH_BASE,
                 search_filter = search_filter,
                 search_scope = SUBTREE,
                 attributes = [EMAIL_PROPERTY,FULL_NAME_PROPERTY],
                 paged_size = 5)

        if len(c.response) > 0:
            dn = c.response[0].get('dn')
            user_email = c.response[0].get('raw_attributes').get(EMAIL_PROPERTY)[0].decode('utf-8')
            full_name = c.response[0].get('raw_attributes').get(FULL_NAME_PROPERTY)[0].decode('utf-8')

            user_conn = Connection(server, auto_bind = True, client_strategy = SYNC, user = dn, password = password, authentication = SIMPLE, check_names = True)

            return (user_email, full_name)

        raise LDAPLoginError({"error_message": "Username or password incorrect"})

    except Exception as e:
        error = "LDAP account or password incorrect: %s" % e
        raise LDAPLoginError({"error_message": error})
