# coding: utf-8

import logging
from urlparse import parse_qs

from django.conf import settings
from django.contrib.auth import logout as auth_logout, authenticate, login, SESSION_KEY, HASH_SESSION_KEY
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.views import login as auth_login_view, logout as auth_logout_view
from django.shortcuts import render_to_response, resolve_url
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.utils.http import is_safe_url
from django import forms
from django.template import RequestContext
from oic.oic.message import EndSessionRequest

from djangooidc.oidc import LazyOIDCClients, OIDCError

logger = logging.getLogger(__name__)

CLIENTS = LazyOIDCClients(settings)

VIEWS_RELATED_SESSION_KEYS = ("op", "dyn_op_hint", "userinfo")


# Step 1: provider choice (form). Also - Step 2: redirect to OP. (Step 3 is OP business.)
class DynamicProvider(forms.Form):
    hint = forms.CharField(required=True, label='OpenID Connect full login', max_length=250)


def is_oidc_redirect_safe_url(request, url):
    if is_safe_url(url, request.get_host()):
        return True
    for host in getattr(settings, 'OIDC_REDIRECT_SAFE_HOSTS', ()):
        if is_safe_url(url, host):
            return True
    return False


def get_views_related_session_data(session):
    return {
        k: session[k] for k in VIEWS_RELATED_SESSION_KEYS if k in session
    }


def openid(request, op_name=None):
    client = None

    if 'next' in request.GET:
        next_page = request.GET['next']
        if not is_oidc_redirect_safe_url(request, next_page):
            next_page = None
    else:
        next_page = None

    if not next_page:
        next_page = resolve_url(settings.LOGIN_REDIRECT_URL)
    request.session["next"] = next_page

    try:
        dyn = settings.OIDC_ALLOW_DYNAMIC_OP or False
    except AttributeError:
        dyn = False

    try:
        intl = settings.OIDC_ALLOW_INTERNAL_LOGIN or False
    except AttributeError:
        intl = False

    try:
        template_name = settings.OIDC_LOGIN_TEMPLATE
    except AttributeError:
        template_name = 'djangooidc/login.html'

    ilform = None
    form = None
    if request.method == 'POST':
        # Internal login?
        if intl and "internal_login" in request.POST:
            return auth_login_view(request)
        if dyn:
            form = DynamicProvider(request.POST)
            if form.is_valid():
                hint = form.cleaned_data["hint"]
                try:
                    client = CLIENTS.dynamic_client(hint)
                    op_name = request.session["op"] = client.provider_info["issuer"]
                    request.session["dyn_op_hint"] = hint
                except Exception, e:
                    logger.exception("could not create dynamic OIDC client, hint: %r", hint)
                    return render_to_response("djangooidc/error.html",
                                              {"error": e, "debug": settings.DEBUG})
    else:
        if intl:
            ilform = AuthenticationForm()
        if dyn:
            form = DynamicProvider()
        # Try to find an OP client either from the form or from the op_name URL argument
        if op_name is not None:
            try:
                client = CLIENTS[op_name]
            except KeyError:
                Http404('OIDC client not found')
            request.session["op"] = op_name

    # If we were able to determine the OP client, just redirect to it with an authentication request
    if client:
        try:
            return client.create_authn_request(request.session)
        except Exception, e:
            logger.exception("could not create authentication request from OIDC client")
            return render_to_response("djangooidc/error.html",
                                      {"error": e, "debug": settings.DEBUG, "op_name": op_name})

    # Otherwise just render the list+form.
    return render_to_response(template_name,
                              {"op_list": [i for i in settings.OIDC_PROVIDERS if i],
                               'dynamic': dyn, 'internal': intl,
                               'form': form, 'ilform': ilform, "next": request.session["next"]},
                              context_instance=RequestContext(request))


class OIDCClientNotFound(Exception):
    pass


def get_proper_client(op_name):
    try:
        # A static OIDC client defined in settings.OIDC_PROVIDERS or
        # a dynamic client registered in the global OIDCClients instance
        # of the current process
        client = CLIENTS[op_name]
    except KeyError:
        if "dyn_op_hint" not in request.session:
            # Not a dynamic OIDC client
            logger.error('OIDC client not found')
            raise OIDCClientNotFound('OIDC client not found')
        # In a multi-processing deployment, a dynamic OIDC client may not be
        # registered in the current process. Get the hint and create it.
        hint = request.session["dyn_op_hint"]
        try:
            client = CLIENTS.dynamic_client(hint)
        except Exception, e:
            logger.exception("could not create dynamic OIDC client, hint: %r", hint)
            raise
    return client


# Step 4: analyze the token returned by the OP
def authz_cb(request):
    try:
        op_name = request.session["op"]
    except KeyError:
        logger.error('could not get "op" key from request session')
        return render_to_response("djangooidc/error.html",
                                  {"error": e, "debug": settings.DEBUG})

    try:
        client = get_proper_client(op_name)
    except OIDCClientNotFound, e:
        return render_to_response("djangooidc/error.html",
                                  {"error": e, "debug": settings.DEBUG})
    except OIDCError, e:
        return render_to_response("djangooidc/error.html",
                                  {"error": e, "debug": settings.DEBUG, "op_name": op_name})

    query = parse_qs(request.META['QUERY_STRING'])
    userinfo = None
    try:
        userinfo = client.callback(query, request.session)
        request.session["userinfo"] = userinfo
        user = authenticate(**userinfo)
        if user:
            # Check whether the current session represent the same user (and with the same session_auth_hash).
            # If true, skip login process (which unnecessarily rotates CSRF token and sends login signal).
            need_login = False
            session_will_flush = False
            if SESSION_KEY in request.session:
                new_session_key = user._meta.pk.value_to_string(user)
                if request.session[SESSION_KEY] != new_session_key:
                    need_login = True
                    session_will_flush = True
                else:
                    new_session_auth_hash = ''
                    if hasattr(user, 'get_session_auth_hash'):
                        new_session_auth_hash = user.get_session_auth_hash()
                    if new_session_auth_hash and request.session[HASH_SESSION_KEY] != new_session_auth_hash:
                        need_login = True
                        session_will_flush = True
            else:
                # Session won't flush for anonymous user, only cycling key
                need_login = True

            # Get and clear next page in session anyway
            next_page = request.session.pop("next", "/")

            if need_login:
                if session_will_flush:
                    # Keep a copy of OIDC login related session data ("op", etc) before flushing
                    old_session_data = get_views_related_session_data(request.session)
                    old_session_data.update(client.get_related_session_data(request.session))
                # Log user in
                login(request, user)
                if session_will_flush:
                    # Restore OIDC login related session data from the copy
                    request.session.update(old_session_data)

            return HttpResponseRedirect(next_page)
        else:
            raise OIDCError('this login is not valid in this application, user not authenticated')
    except OIDCError, e:
        logger.exception('failed to authenticate user, userinfo: %r', userinfo)
        return render_to_response("djangooidc/error.html",
                                  {"error": e, "callback": query, "debug": settings.DEBUG, "op_name": op_name})


def logout(request, next_page=None):
    if not "op" in request.session:
        return auth_logout_view(request, next_page)

    op_name = request.session["op"]

    try:
        client = get_proper_client(op_name)
    except OIDCClientNotFound, e:
        logger.exception('lgout() error:')
        return render_to_response("djangooidc/error.html",
                                  {"error": e, "debug": settings.DEBUG})
    except OIDCError, e:
        logger.exception('lgout() error:')
        return render_to_response("djangooidc/error.html",
                                  {"error": e, "debug": settings.DEBUG, "op_name": op_name})

    # Only resolve URL for internal code usage
    if next_page is not None:
        next_page = resolve_url(next_page)

    # User is by default NOT redirected to the app - it stays on an OP page after logout.
    # Here we determine if a redirection to the app was asked for and is possible.
    if next_page is None and "next" in request.GET:
        next_page = request.GET['next']
    if next_page is None and "next" in request.session:
        next_page = request.session['next']

    if not is_oidc_redirect_safe_url(request, next_page):
        next_page = None

    extra_args = {}
    urls = client.registration_response.get("post_logout_redirect_uris", None)
    if urls:
        # Try to use the registered redirection point
        logout_cb_url = resolve_url('openid_logout_cb')
        for url in urls:
            if logout_cb_url in url:
                extra_args["post_logout_redirect_uri"] = url
                break
        else:
            # Just take the first registered URL as a desperate attempt to come back to the application
            extra_args["post_logout_redirect_uri"] = urls[0]
    else:
        # No post_logout_redirect_uris registered at the OP - no redirection to the application is possible anyway
        pass

    # Redirect client to the OP logout page
    request_args = None
    if '_id_token' in request.session:
        request_args = {'id_token_hint': request.session['_id_token']}
    url, body, ht_args, csi = client.request_info(request=EndSessionRequest,
                                                  method='GET',
                                                  request_args=request_args,
                                                  extra_args=extra_args,
                                                  state=request.session["state"])
    # Log out the current user
    auth_logout(request)
    # Save the next page in the (anonymous) session
    if next_page:
        request.session['next'] = next_page
    return HttpResponseRedirect(bytes(url))


def logout_cb(request):
    """ Simple redirection view: after logout, just redirect to a parameter value inside the session """
    next_page = request.session.pop("next", "/")
    return HttpResponseRedirect(next_page)
