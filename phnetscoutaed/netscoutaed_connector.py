#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Phantom sample App Connector python file
# -----------------------------------------

# Python 3 Compatibility imports
from __future__ import print_function, unicode_literals

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from netscoutaed_consts import *
import requests
import json
from bs4 import BeautifulSoup

class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))

class NetscoutAedConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(NetscoutAedConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._server_url = None
        self._api_token = None
        self._verify_server_cert = False

        return

    def _process_empty_response(self, response, action_result):
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # Create a URL to connect to
        url = self._base_url + endpoint
        self.save_progress(url)

        try:
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                verify=config.get('verify_server_cert', False),
                **kwargs
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )

        if method == 'delete' and r.status_code == 204:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):
        """ This function is used to test the connectivity to the configured asset

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # Make rest call
        ret_val, response = self._make_rest_call(
            NETSCOUTAED_REST_SUMMARY, action_result, params=None, method='get', headers={
                'X-Arbux-APIToken': self._api_token,
                'Accept': 'application/json'
            }
        )

        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status(phantom.APP_ERROR)

        # Return success
        action_result.add_data(response)

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_outbound_allowed_hosts(self, param):
        """ This function is used to list outbound allowed hosts.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Make rest call
        ret_val, response = self._make_rest_call(
            NETSCOUTAED_REST_OUTBOUND_ALLOWED_HOSTS, action_result, params=None, method='get', headers={
                'X-Arbux-APIToken': self._api_token,
                'Accept': 'application/json'
            }
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        hosts = response.pop('allowed-hosts')

        # Add the response into the data section
        action_result.add_data(response)
        action_result.update_summary({'num_hosts': len(hosts)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_outbound_denied_hosts(self, param):
        """ This function is used to list outbound denied hosts.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Make rest call
        ret_val, response = self._make_rest_call(
            NETSCOUTAED_REST_OUTBOUND_DENIED_HOSTS, action_result, params=None, headers={
                'X-Arbux-APIToken': self._api_token,
                'Accept': 'application/json'
            }
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        hosts = response.pop('denied-hosts')

        # Add the response into the data section
        action_result.add_data(response)
        action_result.update_summary({'num_hosts': len(hosts)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_inbound_allowed_hosts(self, param):
        """ This function is used to list inbound allowed hosts

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Access action parameters passed in the 'param' dictionary

        # Required values can be accessed directly
        # required_parameter = param['required_parameter']

        # Optional values should use the .get() function
        # optional_parameter = param.get('optional_parameter', 'default_value')

        # make rest call
        ret_val, response = self._make_rest_call(
            NETSCOUTAED_REST_INBOUND_ALLOWED_HOSTS, action_result, params=None, method='get', headers={
                'X-Arbux-APIToken': self._api_token,
                'Accept': 'application/json'
            }
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()
        hosts = response.pop('allowed-hosts')

        # Add the response into the data section
        action_result.add_data(response)
        action_result.update_summary({'num_hosts': len(hosts)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_inbound_denied_hosts(self, param):
        """ This function is used to list inbound denied hosts

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Make rest call
        ret_val, response = self._make_rest_call(
            NETSCOUTAED_REST_INBOUND_DENIED_HOSTS, action_result, params=None, method='get', headers={
                'X-Arbux-APIToken': self._api_token,
                'Accept': 'application/json'
            }
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status(phantom.APP_ERROR)

        # Add the response into the data section
        hosts = response.pop('denied-hosts')

        # Add the response into the data section
        action_result.add_data(response)
        action_result.update_summary({'num_hosts': len(hosts)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_block_inbound_host(self, param):
        """ This function is used to add host(s) to the inbound denied host list

        :param param: dictionary of input parameters
        :param host: host list (required)
        :param cid: central configuration ID (defaults to null)
        :param pgid: protection group ID (defaults to null)
        :param annotation: annotation
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        host = param['host']
        cid = param.get('cid', 'null')
        pgid = param.get('pgid', 'null')
        annotation = param.get('annotation', NETSCOUTAED_DEFAULT_ANNOTATION)

        # Build JSON for the request
        json_data = {}

        # If both cid and pgid are not defined the configuration will default to the global protection group (pgid = -1)
        if cid == 'null' and pgid == 'null':
            json_data["pgid"] = '-1'
            self.save_progress("No central configuration id (cid) or protection group (pgid) was selected")
            self.save_progress("Defaulting to global protection group")

        elif cid != 'null' and pgid == 'null':
            json_data["cid"] = cid

        elif cid == 'null' and pgid != 'null':
            json_data["pgid"] = pgid

        json_data["hostAddress"] = host.split(",")
        json_data["annotation"] = annotation

        json_data = json.dumps(json_data).replace("'", '"')

        self.save_progress(json_data)

        # Make rest call
        ret_val, response = self._make_rest_call(
            NETSCOUTAED_REST_INBOUND_DENIED_HOSTS, action_result, params=None, data=json_data, method='post', headers={
                'X-Arbux-APIToken': self._api_token,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        try:
            hosts = response.pop('hosts')
            action_result.update_summary({'num_hosts': len(hosts)})
        except:
            action_result.update_summary({'num_hosts': '1'})

        return action_result.set_status(phantom.APP_SUCCESS)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        # return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_unblock_inbound_host(self, param):
        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        host = param['host']
        cid = param.get('cid', 'null')
        pgid = param.get('pgid', 'null')

        # Build JSON for the request
        json_params = {}

        json_params['hostAddress'] = host

        if cid != 'null' and pgid != 'null':
            return action_result.get_status(phantom.APP_ERROR, "cid and pgid cannot be used together")
        if cid != 'null':
            json_params['cid'] = cid
        if pgid != 'null':
            json_params['pgid'] = pgid

        self.save_progress(json_params)

        # Make rest call
        ret_val, response = self._make_rest_call(
            NETSCOUTAED_REST_INBOUND_DENIED_HOSTS, action_result, method='delete', params=json_params, headers={
                'X-Arbux-APIToken': self._api_token,
                'Accept': 'application/json'
            }
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        # summary = action_result.update_summary({})
        # summary['num_data'] = len(action_result['data'])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

        # For now return Error with a message, in case of success we don't set the message, but use the summary
        # return action_result.set_status(phantom.APP_ERROR, "Action not yet implemented")

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'block_ip':
            ret_val = self._handle_block_ip(param)

        if action_id == 'unblock_ip':
            ret_val = self._handle_unblock_ip(param)

        if action_id == 'allow_ip':
            ret_val = self._handle_allow_ip(param)

        if action_id == 'disallow_ip':
            ret_val = self._handle_disallow_ip(param)

        if action_id == 'block_inbound_host':
            ret_val = self._handle_block_inbound_host(param)

        if action_id == 'unblock_inbound_host':
            ret_val = self._handle_unblock_inbound_host(param)

        if action_id == 'list_outbound_allowed_hosts':
            ret_val = self._handle_list_outbound_allowed_hosts(param)

        if action_id == 'list_outbound_denied_hosts':
            ret_val = self._handle_list_outbound_denied_hosts(param)

        if action_id == 'list_inbound_allowed_hosts':
            ret_val = self._handle_list_inbound_allowed_hosts(param)

        if action_id == 'list_inbound_denied_hosts':
            ret_val = self._handle_list_inbound_denied_hosts(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        if action_id == 'block_inbound_host':
            ret_val = self._handle_block_inbound_host(param)

        if action_id == 'unblock_inbound_host':
            ret_val = self._handle_unblock_inbound_host(param)

        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        self._base_url = config[NETSCOUTAED_TA_CONFIG_SERVER_URL].strip("/")
        self._api_token = config[NETSCOUTAED_TA_CONFIG_API_TOKEN]
        self._verify_server_cert = config.get(NETSCOUTAED_TA_CONFIG_VERIFY_SSL)

        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = NetscoutAedConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False, timeout=60)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, timeout=60, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = NetscoutAedConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
