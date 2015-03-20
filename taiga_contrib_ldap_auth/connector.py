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

from ldap3 import Server, Connection, AUTH_SIMPLE, STRATEGY_SYNC, SUBTREE

from django.conf import settings
from taiga.base.connectors.exceptions import ConnectorBaseException


class LDAPLoginError(ConnectorBaseException):
    pass


SERVER = getattr(settings, "LDAP_SERVER", "")
DN_FORMAT = getattr(settings, "LDAP_DN_FORMAT", "")
UID_FORMAT = getattr(settings, "LDAP_UID_FORMAT", "")
AUTH_DN_FORMAT = UID_FORMAT+"={username},"+DN_FORMAT
BASE_EMAIL = getattr(settings, "LDAP_BASE_EMAIL", "")
MAIL_FORMAT = getattr(settings, "LDAP_MAIL_FORMAT", "")
FULLNAME_FORMAT = getattr(settings, "LDAP_FULLNAME_FORMAT", "")


def login(username: str, password: str) -> tuple:
    dn = AUTH_DN_FORMAT.format(username=username)
    c = None
    try:
        server = Server(SERVER)
        c = Connection(server, auto_bind=True, client_strategy=STRATEGY_SYNC,
                   user=dn, password=password, authentication=AUTH_SIMPLE,
                   check_names=True)
    except:
        raise LDAPLoginError({"error_message": "LDAP account or password incorrect."})

    email = None
    full_name = None
    if c is not None:
        c.search(DN_FORMAT,'('+UID_FORMAT+'='+username+')', SUBTREE, attributes = [MAIL_FORMAT,FULLNAME_FORMAT])
        if c.entries is not None:
            for entry in c.entries:
                email = entry.mail[0]
                full_name = entry.cn[0]
    else:
        #Fallback to defaults if we can't get username and email from ldap
        email = username + BASE_EMAIL
        full_name = username
    return (email, full_name)
