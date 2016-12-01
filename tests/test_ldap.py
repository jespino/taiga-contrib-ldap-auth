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

import pytest
import sys

sys.path.append("../taiga-back/")

from unittest.mock import patch, Mock
from taiga_contrib_ldap_auth import connector

def test_ldap_login_success():
    BASE_EMAIL = "@example.com"
    with patch("taiga_contrib_ldap_auth.connector.Server") as m_server, \
            patch("taiga_contrib_ldap_auth.connector.Connection") as m_connection, \
            patch("taiga_contrib_ldap_auth.connector.BASE_EMAIL", new=BASE_EMAIL):
        m_server.return_value = Mock()
        m_connection.return_value = Mock()

        login = "**userName**"
        password = "**password**"
        (username, email, full_name) = connector.login(login, password)
        assert username == login
        assert email == login + BASE_EMAIL
        assert full_name == login


def test_ldap_login_fail():
    with pytest.raises(connector.LDAPLoginError) as e:
        login = "**userName**"
        password = "**password**"
        auth_info = connector.login(login, password)

    assert e.value.status_code == 400
    assert "error_message" in e.value.detail
