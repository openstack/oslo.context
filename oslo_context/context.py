# Copyright 2011 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
Base class for holding contextual information of a request

This class has several uses:

* Used for storing security information in a web request.
* Used for passing contextual details to oslo.log.

Projects should subclass this class if they wish to enhance the request
context or provide additional information in their specific WSGI pipeline
or logging context.
"""

import inspect
import itertools
import threading
import uuid


_request_store = threading.local()

# These arguments will be passed to a new context from the first available
# header to support backwards compatibility.
_ENVIRON_HEADERS = {'auth_token': ['HTTP_X_AUTH_TOKEN',
                                   'HTTP_X_STORAGE_TOKEN'],
                    'user': ['HTTP_X_USER_ID',
                             'HTTP_X_USER'],
                    'tenant': ['HTTP_X_PROJECT_ID',
                               'HTTP_X_TENANT_ID',
                               'HTTP_X_TENANT'],
                    'user_domain': ['HTTP_X_USER_DOMAIN_ID'],
                    'project_domain': ['HTTP_X_PROJECT_DOMAIN_ID']}


def generate_request_id():
    """Generate a unique request id."""
    return 'req-%s' % uuid.uuid4()


class RequestContext(object):

    """Helper class to represent useful information about a request context.

    Stores information about the security context under which the user
    accesses the system, as well as additional request information.
    """

    user_idt_format = u'{user} {tenant} {domain} {user_domain} {p_domain}'

    def __init__(self, auth_token=None, user=None, tenant=None, domain=None,
                 user_domain=None, project_domain=None, is_admin=False,
                 read_only=False, show_deleted=False, request_id=None,
                 resource_uuid=None, overwrite=True, roles=None):
        """Initialize the RequestContext

        :param overwrite: Set to False to ensure that the greenthread local
                          copy of the index is not overwritten.
        """
        self.auth_token = auth_token
        self.user = user
        self.tenant = tenant
        self.domain = domain
        self.user_domain = user_domain
        self.project_domain = project_domain
        self.is_admin = is_admin
        self.read_only = read_only
        self.show_deleted = show_deleted
        self.resource_uuid = resource_uuid
        self.roles = roles or []
        if not request_id:
            request_id = generate_request_id()
        self.request_id = request_id
        if overwrite or not get_current():
            self.update_store()

    def update_store(self):
        """Store the context in the current thread."""
        _request_store.context = self

    def to_policy_values(self):
        """A dictionary of context attributes to enforce policy with.

        oslo.policy enforcement requires a dictionary of attributes
        representing the current logged in user on which it applies policy
        enforcement. This dictionary defines a standard list of attributes that
        should be available for enforcement across services.

        It is expected that services will often have to override this method
        with either deprecated values or additional attributes used by that
        service specific policy.
        """
        return {'user_id': self.user,
                'user_domain_id': self.user_domain,
                'project_id': self.tenant,
                'project_domain_id': self.project_domain,
                'roles': self.roles}

    def to_dict(self):
        """Return a dictionary of context attributes."""
        user_idt = (
            self.user_idt_format.format(user=self.user or '-',
                                        tenant=self.tenant or '-',
                                        domain=self.domain or '-',
                                        user_domain=self.user_domain or '-',
                                        p_domain=self.project_domain or '-'))

        return {'user': self.user,
                'tenant': self.tenant,
                'domain': self.domain,
                'user_domain': self.user_domain,
                'project_domain': self.project_domain,
                'is_admin': self.is_admin,
                'read_only': self.read_only,
                'show_deleted': self.show_deleted,
                'auth_token': self.auth_token,
                'request_id': self.request_id,
                'resource_uuid': self.resource_uuid,
                'roles': self.roles,
                'user_identity': user_idt}

    def get_logging_values(self):
        """Return a dictionary of logging specific context attributes."""
        values = self.to_dict()
        return values

    @classmethod
    def from_dict(cls, values):
        """Construct a context object from a provided dictionary."""
        allowed = [arg for arg in
                   inspect.getargspec(RequestContext.__init__).args
                   if arg != 'self']
        kwargs = {k: v for (k, v) in values.items() if k in allowed}
        return cls(**kwargs)

    @classmethod
    def from_environ(cls, environ, **kwargs):
        """Load a context object from a request environment.

        If keyword arguments are provided then they override the values in the
        request environment.

        :param environ: The environment dictionary associated with a request.
        :type environ: dict
        """
        # Load a new context object from the environment variables set by
        # auth_token middleware. See:
        # http://docs.openstack.org/developer/keystonemiddleware/api/keystonemiddleware.auth_token.html#what-auth-token-adds-to-the-request-for-use-by-the-openstack-service

        # add kwarg if not specified by user from a list of possible headers
        for k, v_list in _ENVIRON_HEADERS.items():
            if k in kwargs:
                continue

            for v in v_list:
                if v in environ:
                    kwargs[k] = environ[v]
                    break

        if 'roles' not in kwargs:
            roles = environ.get('HTTP_X_ROLES', environ.get('HTTP_X_ROLE'))
            roles = [r.strip() for r in roles.split(',')] if roles else []
            kwargs['roles'] = roles

        return cls(**kwargs)


def get_admin_context(show_deleted=False):
    """Create an administrator context."""
    context = RequestContext(None,
                             tenant=None,
                             is_admin=True,
                             show_deleted=show_deleted,
                             overwrite=False)
    return context


def get_context_from_function_and_args(function, args, kwargs):
    """Find an arg of type RequestContext and return it.

       This is useful in a couple of decorators where we don't
       know much about the function we're wrapping.
    """

    for arg in itertools.chain(kwargs.values(), args):
        if isinstance(arg, RequestContext):
            return arg

    return None


def is_user_context(context):
    """Indicates if the request context is a normal user."""
    if not context or not isinstance(context, RequestContext):
        return False
    if context.is_admin:
        return False
    return True


def get_current():
    """Return this thread's current context

    If no context is set, returns None
    """
    return getattr(_request_store, 'context', None)
