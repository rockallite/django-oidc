# coding: utf-8

from django.conf import settings
from django.utils import six
from django.utils.functional import LazyObject
from django.utils.module_loading import import_string
from oic.exception import MissingAttribute
from oic import oic, rndstr
from oic.oauth2 import ErrorResponse
from oic.oic import RegistrationResponse, AuthorizationRequest
from oic.oic import ProviderConfigurationResponse, AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from future.types.newstr import newstr

__author__ = 'roland'

import logging
from django.http import HttpResponseRedirect

logger = logging.getLogger(__name__)

default_ssl_check = getattr(settings, 'OIDC_VERIFY_SSL', True)


class OIDCError(Exception):
    pass


class Client(oic.Client):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_method=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        oic.Client.__init__(self, client_id, ca_certs, client_prefs,
                            client_authn_method, keyjar, verify_ssl)
        if behaviour:
            self.behaviour = behaviour

    def create_authn_request(self, session, acr_value=None, **kwargs):
        session["state"] = rndstr()
        session["nonce"] = rndstr()
        request_args = {
            "response_type": self.behaviour["response_type"],
            "scope": self.behaviour["scope"],
            "state": session["state"],
            "nonce": session["nonce"],
            "redirect_uri": self.registration_response["redirect_uris"][0]
        }

        if acr_value is not None:
            request_args["acr_values"] = acr_value

        request_args.update(kwargs)
        cis = self.construct_AuthorizationRequest(request_args=request_args)
        logger.debug("request: %s" % cis)

        url, body, ht_args, cis = self.uri_and_body(AuthorizationRequest, cis,
                                                    method="GET",
                                                    request_args=request_args)

        logger.debug("body: %s", body)
        logger.info("URL: %s", url)
        logger.debug("ht_args: %s", ht_args)

        if isinstance(url, newstr):
            p3_bytes = bytes(url)
            url = p3_bytes.decode('utf-8', 'surrogateescape')
        resp = HttpResponseRedirect(url)
        if ht_args:
            for key, value in ht_args.items():
                resp[key] = value
        logger.debug("resp_headers: %s" % ht_args)
        return resp

    def callback(self, response, session):
        """
        This is the method that should be called when an AuthN response has been
        received from the OP.

        :param response: The URL returned by the OP
        :return:
        """
        authresp = self.parse_response(AuthorizationResponse, response,
                                       sformat="dict", keyjar=self.keyjar)

        if isinstance(authresp, ErrorResponse):
            if authresp["error"] == "login_required":
                return self.create_authn_request(session)
            else:
                raise OIDCError("Access denied")

        if session["state"] != authresp["state"]:
            raise OIDCError("Received state not the same as expected.")

        try:
            if authresp["id_token"] != session["nonce"]:
                raise OIDCError("Received nonce not the same as expected.")
            self.id_token[authresp["state"]] = authresp["id_token"]
        except KeyError:
            pass

        if self.behaviour["response_type"] == "code":
            # get the access token
            try:
                args = {
                    "code": authresp["code"],
                    "redirect_uri": self.registration_response["redirect_uris"][0],
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }

                atresp = self.do_access_token_request(
                    scope="openid", state=authresp["state"], request_args=args,
                    authn_method=self.registration_response["token_endpoint_auth_method"])
            except Exception as err:
                logger.error("%s" % err)
                raise

            if isinstance(atresp, ErrorResponse):
                raise OIDCError("Invalid response %s." % atresp["error"])
            session['id_token'] = atresp['id_token']._dict
            session['_id_token'] = atresp['_id_token']
            session['access_token'] = atresp['access_token']
            try:
                session['refresh_token'] = atresp['refresh_token']
            except:
                pass

        inforesp = self.do_user_info_request(state=authresp["state"], method="GET")

        if isinstance(inforesp, ErrorResponse):
            raise OIDCError("Invalid response %s." % inforesp["error"])

        userinfo = inforesp.to_dict()

        logger.debug("UserInfo: %s" % inforesp)

        return userinfo


class OIDCClients(object):
    def __init__(self, config):
        """

        :param config: Imported configuration module
        :return:
        """
        self.client = {}
        # You can override default client class in OIDC_DEFAULT_CLIENT_CLS setting
        self.client_cls = getattr(config, 'OIDC_DEFAULT_CLIENT_CLS', Client)
        self.config = config

        for key, val in config.OIDC_PROVIDERS.items():
            if key == "":
                continue
            else:
                self.client[key] = self.create_client(**val)

    @property
    def client_cls(self):
        if isinstance(self._client_cls, six.string_types):
            self._client_cls = import_string(self._client_cls)
        return self._client_cls

    @client_cls.setter
    def client_cls(self, value):
        self._client_cls = value or Client

    def create_client(self, userid="", **kwargs):
        """
        Do an instantiation of a client instance

        :param userid: An identifier of the user
        :param: Keyword arguments
            Keys are ["srv_discovery_url", "client_info", "client_registration",
            "provider_info"]
        :return: client instance
        """

        # You can override client class of a specific OP in OIDC_PROVIDERS setting
        client_cls = kwargs.pop('client_cls', None)
        if client_cls:
            if isinstance(client_cls, six.string_types):
                client_cls = import_string(client_cls)
        else:
            client_cls = self.client_cls

        _key_set = set(kwargs.keys())
        args = {}
        for param in ["verify_ssl"]:
            try:
                args[param] = kwargs[param]
            except KeyError:
                pass
            else:
                _key_set.discard(param)

        try:
            verify_ssl = default_ssl_check
        except:
            verify_ssl = True

        client = client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                            behaviour=kwargs["behaviour"], verify_ssl=verify_ssl, **args)

        # The behaviour parameter is not significant for the election process
        _key_set.discard("behaviour")
        for param in ["allow"]:
            try:
                setattr(client, param, kwargs[param])
            except KeyError:
                pass
            else:
                _key_set.discard(param)

        if _key_set == set(["client_info"]):  # Everything dynamic
            # There has to be a userid
            if not userid:
                raise MissingAttribute("Missing userid specification")

            # Find the service that provides information about the OP
            issuer = client.wf.discovery_query(userid)
            # Gather OP information
            _ = client.provider_config(issuer)
            # register the client
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == set(["client_info", "srv_discovery_url"]):
            # Ship the webfinger part
            # Gather OP information
            _ = client.provider_config(kwargs["srv_discovery_url"])
            # register the client
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == set(["provider_info", "client_info"]):
            client.handle_provider_config(
                ProviderConfigurationResponse(**kwargs["provider_info"]),
                kwargs["provider_info"]["issuer"])
            _ = client.register(client.provider_info["registration_endpoint"],
                                **kwargs["client_info"])
        elif _key_set == set(["provider_info", "client_registration"]):
            client.handle_provider_config(
                ProviderConfigurationResponse(**kwargs["provider_info"]),
                kwargs["provider_info"]["issuer"])
            client.store_registration_info(RegistrationResponse(
                **kwargs["client_registration"]))
        elif _key_set == set(["srv_discovery_url", "client_registration"]):
            _ = client.provider_config(kwargs["srv_discovery_url"])
            client.store_registration_info(RegistrationResponse(
                **kwargs["client_registration"]))
        else:
            raise Exception("Configuration error ?")

        return client

    def dynamic_client(self, userid):
        client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD,
                                 verify_ssl=default_ssl_check)

        issuer = client.wf.discovery_query(userid)
        if issuer in self.client:
            return self.client[issuer]
        else:
            # Gather OP information
            _pcr = client.provider_config(issuer)
            # register the client
            _ = client.register(_pcr["registration_endpoint"], **self.config.OIDC_DYNAMIC_CLIENT_REGISTRATION_DATA)
            try:
                client.behaviour.update(**self.config.OIDC_DEFAULT_BEHAVIOUR)
            except KeyError:
                pass

            self.client[issuer] = client
            return client

    def __getitem__(self, item):
        """
        Given a service return a corresponding client
        :param item:
        :return:
        """
        return self.client[item]

    def keys(self):
        return self.client.keys()


class LazyOIDCClients(LazyObject):
    def __init__(self, config):
        super(LazyOIDCClients, self).__init__()
        self.__dict__['config'] = config

    def __copy__(self):
        if self._wrapped is empty:
            # If uninitialized, copy the wrapper. Use type(self), not
            # self.__class__, because the latter is proxied.
            return type(self)(self.config)
        else:
            # If initialized, return a copy of the wrapped object.
            return copy.copy(self._wrapped)

    def __deepcopy__(self, memo):
        if self._wrapped is empty:
            # We have to use type(self), not self.__class__, because the
            # latter is proxied.
            result = type(self)(copy.deepcopy(self.config, memo))
            memo[id(self)] = result
            return result
        return copy.deepcopy(self._wrapped, memo)

    def _setup(self):
        self._wrapped = OIDCClients(self.config)
