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

import itertools
import threading
import uuid


_request_store = threading.local()


def generate_request_id():
    """Generate a unique request id."""
    return 'req-%s' % uuid.uuid4()


class RequestContext(object):

    """Helper class to represent useful information about a request context.

    Stores information about the security context under which the user
    accesses the system, as well as additional request information.
    """

    user_idt_format = '{user} {tenant} {domain} {user_domain} {p_domain}'

    def __init__(self, auth_token=None, user=None, tenant=None, domain=None,
                 user_domain=None, project_domain=None, is_admin=False,
                 read_only=False, show_deleted=False, request_id=None,
                 resource_uuid=None, overwrite=True):
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
        if not request_id:
            request_id = generate_request_id()
        self.request_id = request_id
        if overwrite or not get_current():
            self.update_store()

    def update_store(self):
        """Store the context in the current thread."""
        _request_store.context = self

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
                'user_identity': user_idt}

    def get_logging_values(self):
        """Return a dictionary of logging specific context attributes."""
        values = self.to_dict()
        return values

    @classmethod
    def from_dict(cls, ctx):
        """Construct a context object from a provided dictionary."""
        return cls(
            auth_token=ctx.get("auth_token"),
            user=ctx.get("user"),
            tenant=ctx.get("tenant"),
            domain=ctx.get("domain"),
            user_domain=ctx.get("user_domain"),
            project_domain=ctx.get("project_domain"),
            is_admin=ctx.get("is_admin", False),
            read_only=ctx.get("read_only", False),
            show_deleted=ctx.get("show_deleted", False),
            request_id=ctx.get("request_id"),
            resource_uuid=ctx.get("resource_uuid"))

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
        kwargs.setdefault('auth_token', environ.get('HTTP_X_AUTH_TOKEN'))
        kwargs.setdefault('user', environ.get('HTTP_X_USER_ID'))
        kwargs.setdefault('tenant', environ.get('HTTP_X_PROJECT_ID'))
        kwargs.setdefault('user_domain', environ.get('HTTP_X_USER_DOMAIN_ID'))
        kwargs.setdefault('project_domain',
                          environ.get('HTTP_X_PROJECT_DOMAIN_ID'))

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
