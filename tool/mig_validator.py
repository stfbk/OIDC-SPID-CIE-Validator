import argparse
import os
import jwt
from jwt.exceptions import InvalidTokenError
import json
import jsonschema
from jsonschema import Draft202012Validator
from datetime import datetime, timezone
from authlib.jose import JsonWebKey
import time
from abc import ABC, abstractmethod

from typing import Dict, List, Any, Union
#To style the output from module
from style_table import main

#Managing URL
import urllib.parse
from urllib.parse import urlparse
import requests

#Add colors to terminal
from rich.console import Console

INPUT_SCHEMA = "schemas/"
VERBOSE = False
FEDERATION_URL = ".well-known/openid-federation"
SPID = False

console = Console()

#Class to handle test list
class TestManager:
    #Define the two main lists
    def __init__(self):
        self.simple_output: List[Dict[str, Union[str, bool]]] = [
            {"ID": "1", "Test Name": "Entity Configuration Response", "Test Result": "", "Reason/Mitigation": ""},
            {"ID": "2", "Test Name": "Authorization Request", "Test Result": "", "Reason/Mitigation": ""}
        ]

    #Method to modify the current message to be more clear
    @staticmethod
    def change_error_message(msg: str) -> tuple[str, str]:
        param_name = msg.split("'")[1]
        message = msg.split("'")[-1]
        return param_name, f"This{message}. The property {param_name} is missing in the JSON."
    
    #Method to add a new entry
    def append_test(self, id: str, test_name: str, test_result: Union[str, bool], reason: str):
        #If bool change to the same in str
        if isinstance(test_result, bool):
            test_result = "PASSED" if test_result else "FAILED"

        #Add a new entry to the test
        self.simple_output.append({
            "ID": id,
            "Test Name": test_name,
            "Test Result": test_result,
            "Reason/Mitigation": reason
        })
    
    #Method to update tests based on the IDs
    def update_test(self, test_id: str, key: str, value: Any):
        #Update an entry
        for test in self.simple_output:
            if test["ID"] == test_id:
                if key in test:
                    test[key] = value
                else:
                    console.print(f"Key '{key}' not found in the test dictionary.", style="bold red")
                return
        console.print(f"Test with name '{test_id}' not found.", style="bold red")
    
    #Method to update the Test Result of parent sections based on their subsections' results.
    def update_parent_test(self, test_list: List[Dict[str, Any]]):
        # Sort data by ID to ensure parents are processed before children
        self.simple_output.sort(key=lambda x: [int(part) for part in x["ID"].split('.')])

        # Iterate in reverse order (bottom-up) so subsections are checked before parents
        self.simple_output.sort(key=lambda x: int(x["ID"].split('.')[-1]))
        
        for test in reversed(self.simple_output):
            parent_id = '.'.join(test["ID"].split('.')[:-1])
            parent = next((t for t in self.simple_output if t["ID"] == parent_id), None)
            
            # Only process if this is a subsection (has more than 1 part)
            if parent:
                #If any subsection failed and parent has not already FAILED, mark parent as FAILED and ADD
                if test["Test Result"] in ["FAILED", "[FAILED]"] and not (parent["Test Result"] in ["FAILED", "[FAILED]"] and parent["Reason/Mitigation"]):
                    self.update_test(parent_id, "Test Result", "[FAILED]")
                    self.update_test(parent_id, "Reason/Mitigation", f"Some of the subtests failed. See subsequent, e.g., {test['ID']}.")
                #If parent has no result, check if all subsections are passed
                elif parent["Test Result"] in ["FAILED", "[FAILED]", "PASSED", ""]:
                    siblings = [t for t in self.simple_output if t["ID"].startswith(parent_id + '.')]
                    #If all siblings have passed, set the parent as PASSED
                    if all(s["Test Result"] in ["PASSED", "[PASSED]"] for s in siblings):
                        self.update_test(parent_id, "Test Result", "[PASSED]")
                        self.update_test(parent_id, "Reason/Mitigation", "All subtests passed.")

    #Method to reset to initial state
    def reset(self):
        self.__init__()

#Class to handle saved params
class ParamManager:
    #Define the two main dictionaries, one for section and one for params
    def __init__(self):
        self.section: Dict[str, str] = {"EC": "1.1", "AR": "2.1"}
        self.saved_param: Dict[str, str] = {
            "public_pem": "",
            "redirect_uris": "",
            "response_type": "",
            "exp_date": "",
            "authority_hints": "",
            "iss": "",
            "kid_defaultRSASign":""
        }
    
    #Method to get value by key from a specified dictionary
    @staticmethod
    def get_value(key: str, param_dict: Dict[str, Any]) -> Any:
        return param_dict.get(key)

    #Method to update value by key in a specified dictionary
    @staticmethod
    def update_value(key: str, value: Any, param_dict: Dict[str, Any]):
        if key in param_dict:
            param_dict[key] = value
        else:
            console.print(f"[ERROR] Key '{key}' does not exist in the dictionary. Cannot update.", style="bold red")
    
    #Method to increment the value into a specified dictionary add 1 to last char
    @staticmethod
    def increment_value(key:str, param_dict: Dict[str, str]) -> str:
        if key in param_dict:
            current_value = param_dict[key]
            try:
                #Split the string by "."
                splitted = current_value.split(".")
                #Convert the **last part** to int and increment it
                splitted[-1] = str(int(splitted[-1]) +1)
                #Join it back and update the dict
                new_value = '.'.join(splitted)
                param_dict[key] = new_value
                return current_value
            except ValueError:
                console.print(f"[ERROR] Invalid version format for '{key}' in {param_dict}.", style="bold red")
        else:
            console.print(f"[ERROR] Key '{key}' does not exist in the dictionary. Cannot update.", style="bold red")

    #Method to add a new key-value pair to a specified dictionary
    @staticmethod
    def add_value(key:str, value: Any, param_dict: Dict[str, Any]):
        param_dict[key] = value
    
    #Method to save the kid value
    def save_kid(self, keys: List[Dict[str, Any]]):
        if keys:
            for k in keys:
                if k.get("use")=="sig" or not bool(k.get("use")):
                    if k.get("kid") not in self.saved_param and bool(k.get("kid")):
                        #Create key
                        key = JsonWebKey.import_key(k)
                        binary_key = key.as_pem(is_private=False)
                        #Save kid and key
                        self.add_value(k["kid"], binary_key.decode('utf-8'), self.saved_param)
                        #Update defaultRSA
                        self.update_value("kid_defaultRSASign", k["kid"], self.saved_param)

    #Method to reset param_store to the original state
    def reset(self):
        self.__init__()

#Class that provides methods for validating various data formats, .g., schema, signature
class Validator(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def validate(self, jwt_input: str, input_data: Dict[str, Any], msg: str) -> None:
        if jwt_input:
            if isinstance(jwt_input, list):
                jwt_input = jwt_input[0]
            self.decoded_body, self.alg, self.kid = Validator.validate_and_decode_jwt(input_data, jwt_input, msg)
            self.additional_checks(self.decoded_body, self.kid)
            Validator.validate_signature(jwt_input, self.alg, param_manager.get_value(msg, param_manager.section), self.kid)

    @abstractmethod
    def additional_checks(decoded_body: str, kid: str):
        pass

    @staticmethod
    def is_jwt(token:str) -> bool:
        return len(token.split('.')) == 3
    
    @staticmethod
    def is_https_url(url: str) -> bool:
        return urllib.parse.urlparse(url).scheme == "https"
    
    @staticmethod
    def validate_schema (part:dict, schema:dict, which_schema:str, msg:str):
        #part = {'kid': 'E6BBD2AF6E03374BC8BF51E48C40C39C90177AED', 'typ': 'entity-statement+jwt', 'alg': 'RS256'}
        msg = msg + " " + which_schema
        main_id = ".".join(param_manager.get_value(msg, param_manager.section).split(".")[:-1])

        try:
            validator = Draft202012Validator(schema)
            errors = sorted(validator.iter_errors(part), key=lambda e: e.path)

            if errors:
                #which_schema dice se header o payload, msg dice se EC, AR o TM{i}
                test_manager.append_test(main_id, "JWT "+ which_schema, "[FAILED]", "")

                for i, error in enumerate(errors, 1):
                    # Format the error path (handle nested paths)
                    path_error = ".".join(str(p) for p in error.path) or ""
                    if path_error:
                        test_manager.append_test(param_manager.increment_value(msg, param_manager.section), "$."+path_error, "FAILED", error.message)
                    else:
                        keyitem, message = test_manager.change_error_message(error.message)
                        test_manager.append_test(param_manager.increment_value(msg, param_manager.section), "$."+keyitem , "FAILED", message)
                
            else:
                #No error, for sure the main ID, e.g, Header, Payload, Signature
                test_manager.append_test(main_id, "JWT " + which_schema, "[PASSED]", "")

        except Exception as e:
            console.print(f"[ERROR] Unexpected error during schema validation: {str(e)}", style="bold red")

    @staticmethod
    def validate_signature (jwt_input: Dict[str, Any], alg: int, section: str, kid: str):
        if kid == "defaultRSASign":
            kid="kid_defaultRSASign"
        kid = param_manager.get_value(kid, param_manager.saved_param)
        
        if not kid:
            test_manager.append_test(section, "Signature", "[MISSING]", "The PUBLIC_KEY is missing, missing kid. Cannot perform the check")
            return

        if not url_rp:
            test_manager.append_test(section, "Signature", "[MISSING]", "The PUBLIC_KEY is missing, missing URL. Cannot perform the check")
            return
        
        try:
            # Decode and validate the JWT
            decoded_payload = jwt.decode(
                jwt_input.strip(),
                kid,
                algorithms=[alg],
                options={"verify_aud": False, "verify_exp": False},
                leeway=300 #5minutes
            )
            test_manager.append_test(section, "Signature", "[PASSED]", "The signature for JWT is valid and correct.")
        except InvalidTokenError as e:
            test_manager.append_test(section, "Signature", "[FAILED]", f"Signature for JWT failed: {str(e)}")
        except Exception as e:
            test_manager.append_test(section, "Signature", "[ERROR]", f"An unexpected error occurred: {str(e)}")

    @classmethod
    def validate_and_decode_jwt(cls, schemas:dict, jwt_input:str, msg:str):
        #Add Header and Payload
        param_manager.add_value(msg+" Header", param_manager.increment_value(msg, param_manager.section)+".1", param_manager.section)
        param_manager.add_value(msg+" Payload", param_manager.increment_value(msg, param_manager.section)+".1", param_manager.section)
        
        #Check if it is REALLY a JWT, if not raise an Error
        test_manager.append_test(param_manager.increment_value(msg, param_manager.section), "Valid JWT", cls.is_jwt(jwt_input), f"It MUST be a valid JWT")

        if cls.is_jwt (jwt_input):
            #For TM there is the number only on the message but not on the schema
            entity = msg[:-1] if "TM" in msg else msg

            #Access the loaded schemas
            header_schema = schemas.get(entity+'_header_schema')
            body_schema = schemas.get(entity+'_body_schema')

            try:
                #Decode header and body of the JWT without verifying the signature
                decoded_body = jwt.decode(jwt_input.replace('\n',''), options={"verify_signature": False})
                decoded_header = jwt.get_unverified_header(jwt_input.replace('\n',''))
                
                #Save alg and kid for future usage
                alg = decoded_header.get('alg', "")
                kid = decoded_header.get('kid', "")

                if header_schema:
                    cls.validate_schema(decoded_header, header_schema, "Header", msg)
                else:
                    console.print(f"[ERROR] The {msg} header schema has not been loaded", style="bold red")

                if body_schema:
                    cls.validate_schema(decoded_body, body_schema, "Payload", msg)
                else:
                    console.print(f"[ERROR] The {msg} payload schema has not been loaded", style="bold red")

            except jsonschema.exceptions.ValidationError as e:
                console.print(f"[ERROR] Schema validation error: {e.message}", style="bold red")
                return False
            except jwt.exceptions.DecodeError as e:
                console.print(f"[ERROR] JWT decoding error for {msg}: {e}", style="bold red")
                return False
            
            return decoded_body, alg, kid

        else:
            console.print(f"[ERROR] The downloaded {msg} content does not contain a valid JWT.", style="bold red")

class ECValidator(Validator):
    def __init__(self):
        self.decoded_body = None
    
    def get_decoded_body(self):
        return self.decoded_body

    def validate(self, jwt_input: str, input_data: Dict[str, Any], msg: str) -> None:
        super().validate(jwt_input, input_data, msg)

    def additional_checks(self, decoded_body:str, kid:str):
        self.decoded_body=decoded_body
        #First check: $.[iss]==$.[sub]
        iss = decoded_body.get('iss', "")
        sub = decoded_body.get('sub', "")
        if iss and sub:
            test_manager.append_test(param_manager.increment_value("EC Payload", param_manager.section), "$.iss == $.sub", iss==sub, f"Both issuer and subject value in Entity Configuration JWT MUST be present and have the same value\n  iss: {iss}\n  sub: {sub}")
        # save iss
        param_manager.update_value("iss", iss, param_manager.saved_param)

        #Second check: $.[iat] < $.[exp]
        iat = decoded_body.get('iat')
        exp = decoded_body.get('exp')
        if iat and exp:
            exp_date = datetime.fromtimestamp(int(exp), timezone.utc)
            iat_date = datetime.fromtimestamp(int(iat), timezone.utc)
            test_manager.append_test(param_manager.increment_value("EC Payload", param_manager.section), "$.iat < $.exp", (iat<exp), f"The issuance date, {str(iat_date)}, MUST be earlier than the expiration date, {str(exp_date)}.")
            test_manager.append_test(param_manager.increment_value("EC Payload", param_manager.section), "current_time < $.exp", (time.time()<exp), f"The expiration date MUST be valid and not passed. The expiration date is: {str(exp_date)}")
        else:
            exp_date = ""

        keys = decoded_body.get('jwks', {}).get('keys', [])
        param_manager.save_kid(keys)
        
        #Data to be saved:
        # a. exp_date
        param_manager.update_value("exp_date", exp_date, param_manager.saved_param)

        if bool(decoded_body.get('metadata',{}).get('openid_relying_party',{})):
            #Third check: $.metadata.openid_relying_party[client_id] == URL_RP
            client_id = decoded_body['metadata']['openid_relying_party'].get('client_id')
            if client_id and iss:
                test_manager.append_test(param_manager.increment_value("EC Payload", param_manager.section), "$.metadata.openid_relying_party[client_id] == issuer", client_id == iss, f"The client_id from Entity Configuration Payload JSON in the path of '$.metadata.openid_relying_party' MUST be an HTTPS URL that uniquely identifies the RP:\n  client_id: {client_id}\n issuer: {iss}")
            
            # b. public_pem
            jwk_keys = decoded_body['metadata']['openid_relying_party'].get('jwks', {}).get('keys', [])
            param_manager.save_kid(jwk_keys)
            
            # e1. Check it is the same of the one in header
            test_manager.append_test(param_manager.increment_value("EC Payload", param_manager.section), "kid == $.metadata.openid_relying_party.jwks.keys[kid]", kid in param_manager.saved_param, "The kid in the header MUST be the same of the signing kid in the metadata")

            # c. $.metadata.openid_relying_party[redirect_uris]
            param_manager.update_value("redirect_uris", decoded_body['metadata']['openid_relying_party'].get('redirect_uris', []), param_manager.saved_param)

            # d. $.metadata.openid_relying_party[response_type]
            param_manager.update_value("response_type", decoded_body['metadata']['openid_relying_party'].get('response_types', []), param_manager.saved_param)

        # f. $.authority_hints
        param_manager.update_value("authority_hints", decoded_body.get('authority_hints', {}), param_manager.saved_param)              

class TMValidator(Validator):
    def __init__(self, tm_number):
        self.tm_number = tm_number

    def validate(self, trust_mark_jwt: str, input_data: Dict[str, Any], msg: str) -> None:
        super().validate(trust_mark_jwt, input_data, msg)

    def additional_checks(self, tm_body: list, kid:str):
            #First check: $.[sub]==url_rp
            sub = tm_body.get('sub')
            test_manager.append_test(param_manager.increment_value(f"TM{self.tm_number} Payload", param_manager.section), "$.sub == URL_RP", sub==url_rp, f"The subject in the Trust Mark MUST be present and have the same value of URL Relying Party\n  sub: {sub}\n  url_rp: {url_rp}")

            #Second check: check kid parameter
            test_manager.append_test(param_manager.increment_value(f"TM{self.tm_number} Payload", param_manager.section), "$.kid in $.metadata.openid_relying_party.jwks.keys[kid]", kid in param_manager.saved_param, f"The kid value in the header of the jwt of the Trust Mark MUST be the same of the kid value in the jwks of the Metadata RP.")

            #Third check: check iss is in auth_hints
            iss = tm_body.get('iss')
            authority_hints = param_manager.get_value("authority_hints", param_manager.saved_param)
            test_manager.append_test(param_manager.increment_value(f"TM{self.tm_number} Payload", param_manager.section), "$.iss in $.authority_hints", iss in authority_hints, f"The iss of the Trust Mark MUST be a superior entity, i.e., authority_hints in the Metadata\n iss: {iss}\n authority_hints: {authority_hints}")

            #Fourth check: expiration date must be valid
            exp = tm_body.get('exp', 0)
            iat = tm_body.get('iat', 0)
            if exp:
                exp_date = datetime.fromtimestamp(int(exp), timezone.utc)
                test_manager.append_test(param_manager.increment_value(f"TM{self.tm_number} Payload", param_manager.section), "current_time < $.exp", (time.time()<exp), f"The expiration date MUST be valid and not passed\n  expiration: {str(exp_date)}")
                test_manager.append_test(param_manager.increment_value(f"TM{self.tm_number} Payload", param_manager.section), "$.iat < $.exp", (iat<exp), f"The expiration date MUST be valid and not passed\n  expiration: {str(exp_date)}")

class ARValidator(Validator):
    def __init__(self, ar_params):
        self.ar_params = ar_params

    def validate(self, jwt_input: str, input_data: Dict[str, Any], msg: str) -> None:
        super().validate(jwt_input, input_data, msg)

    def additional_checks(self, decoded_body: str, kid:str):
        #First Check: $.[client_id] == iss
        client_id_body = decoded_body.get('client_id')
        iss = param_manager.get_value('iss', param_manager.saved_param)
        test_manager.append_test(param_manager.increment_value("ARR Payload", param_manager.section), "$.client_id == iss of RP's EntityConfiguration", (client_id_body==iss), f"The client_id in the payload of the JWT Authorization Request MUST be present AND equal to the URL of the Relying Party\n  $.client_id: {client_id_body}\n  iss: {iss}")

        #Second check: # $.[redirect_uri] is in body of the EC $.metadata.openid_relying_party[redirect_uris]
        redirect_uri = decoded_body.get('redirect_uri')
        redirect_uris = param_manager.get_value("redirect_uris", param_manager.saved_param)
        test_manager.append_test(param_manager.increment_value("ARR Payload", param_manager.section), "$.redirect_uri in $.metadata.openid_relying_party[redirect_uris]", redirect_uri is not None and redirect_uri in redirect_uris, f"The redirect_uri in the payload of the JWT Authorization Request payload MUST be present AND in the list of the redirect_uris provided in the Entity Configuration payload\n  $.redirect_uri: {redirect_uri}\n  $.metadata.openid_relying_party.redirect_uris: {redirect_uris}")

        #2b check: # $.[response_type] is in body of the EC $.metadata.openid_relying_party[response_type]
        response_type = decoded_body.get('response_type')
        response_types = param_manager.get_value("response_type", param_manager.saved_param)
        test_manager.append_test(param_manager.increment_value("ARR Payload", param_manager.section), "$.response_type in $.metadata.openid_relying_party[response_type]", response_type is not None and response_type in response_types, f"The response_type in the payload of the JWT Authorization Request payload MUST be present AND in the list of the response_types provided in the Entity Configuration payload\n  $.response_type: {response_type}\n  $.metadata.openid_relying_party.response_types: {response_types}")

        #Third Check: check kid parameter
        test_manager.append_test(param_manager.increment_value("ARR Payload", param_manager.section), "$.kid in $.metadata.openid_relying_party.jwks.keys[kid]", kid in param_manager.saved_param, f"The kid value in the header of the jwt request MUST be the same of the kid value in the jwks of the Metadata RP")

        #Fourth check: expiration date must be valid
        exp = decoded_body.get('exp', 0) 
        if exp:
            exp_date = datetime.fromtimestamp(int(exp), timezone.utc)
            test_manager.append_test(param_manager.increment_value("ARR Payload", param_manager.section), "current_time < $.exp", (time.time()<exp), f"The expiration date MUST be valid and not passed. The expiration date is: {str(exp_date)}")

        #Fifth Check: check presence and value of parameter in HTTP Message
        # a. client_id
        client_id_http = self.ar_params.get('client_id')
        #Only SPID check for the presence
        if SPID:
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "client_id", bool(self.ar_params.get('client_id')), "The client_id parameter MUST be present in the HTTP message of Authorization Request.")
        #If exist check the value
        if bool(self.ar_params.get('client_id')) and isinstance(client_id_http, list):
            client_id_http = client_id_http[0]
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "client_id == $.client_id", (client_id_http==client_id_body), f"Both the client_id in the HTTP_message and in the Payload of the JWT request MUST have the same value\n  client_id: {client_id_http}\n  $.client_id: {client_id_body}")
            #client_id is an HTTPS URL
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "client_id is an HTTPS URL", self.is_https_url(client_id_http), f"The client_id in the HTTP_message MUST be an HTTPS URL\n  client_id: {client_id_http}")

        # a1. client_id == $.iss
        iss_decodedBody=decoded_body.get('iss')
        test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "client_id", client_id_http==iss_decodedBody, f"The client_id in the HTTP message and $.iss parameters in the JWT request MUST be equal.\n  client_id: {client_id_http}\n  $.iss: {iss_decodedBody}")

        # b. response_type
        response_type_http = self.ar_params.get('response_type')
        if SPID:
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "response_type", bool(self.ar_params.get('response_type')), f"The response_type parameter MUST be present in the HTTP message of Authorization Request.")
        if bool(self.ar_params.get('response_type')) and isinstance(response_type_http, list):
            response_type_http = response_type_http[0]
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "'code' in response_type", 'code' in response_type_http, f"The value of response_type in the HTTP_message MUST be 'code'\n  response_type: {response_type_http}")
    
        # c. scope
        scope = self.ar_params.get('scope')
        if bool(self.ar_params.get('scope')) and isinstance(scope, list):
            scope = scope[0]
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "scope", 'openid' in scope, f"The scope parameter MUST contain 'openid'\n  scope: {scope}")
            test_manager.append_test(param_manager.increment_value("ARR", param_manager.section), "scope", scope==decoded_body.get('scope'), f"The scope parameter in the HTTP message and JWT Request of Authorization Request MUST be present and have the same value")
        else:
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "scope", bool(self.ar_params.get('scope')), f"The scope parameter MUST be present in the HTTP message of Authorization Request.")

        # d. code_challenge
        if bool(self.ar_params.get('code_challenge')):
            code_challenge=self.ar_params['code_challenge']
            codeChallenge_decoded=decoded_body.get('code_challenge')
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "code_challenge==$.code_challenge", codeChallenge_decoded in code_challenge, f"The code_challenge in the HTTP message and JWT Request of Authorization Request MUST be present and have the same value.\n  code_challenge: {code_challenge}\n  $.code_challenge: {codeChallenge_decoded}")
        else:
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "code_challenge", "FAILED", f"The code_challenge parameter MUST be present in the HTTP message of Authorization Request.")

        # e. code_challenge_method
        if bool(self.ar_params.get('code_challenge_method')):
            code_challenge_method=self.ar_params['code_challenge_method']
            codeChallengeMethod_decoded=decoded_body.get('code_challenge_method')
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "code_challenge_method==$.code_challenge_method", codeChallengeMethod_decoded in code_challenge_method, f"The code_challenge_method in the HTTP message and JWT Request of Authorization Request MUST be present and have the same value.\n  code_challenge_method: {code_challenge_method}\n  $.code_challenge_method: {codeChallengeMethod_decoded}")
        else:
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "code_challenge_method", bool(self.ar_params.get('code_challenge_method')), f"The code_challenge_method parameter MUST be present in the HTTP message of Authorization Request.")
   
class JWKSValidator(Validator):
    def __init__(self):
        pass

    def validate(self, jwks_uri_jwt: str, input_data: Dict[str, Any], msg: str) -> None:
        super().validate(jwks_uri_jwt, input_data, msg)

#Reset all for restart
def reset_all():
    global url_rp
    global url_ar
    
    url_ar = ""
    url_rp = ""
    test_manager.reset()
    param_manager.reset()

#Method to select all related files (if SPID) from folder
def select_files(is_spid):
    all_files = [f for f in os.listdir(INPUT_SCHEMA) if f.endswith('.json')]
    
    spid_files = [f for f in all_files if '_SPID' in f]
    non_spid_files = [f for f in all_files if '_SPID' not in f]
    
    if is_spid:
        return spid_files + [f for f in non_spid_files 
                             if not any(f.startswith(spid_file.split('_SPID')[0]) for spid_file in spid_files)]
    else:
        return [f for f in all_files if '_SPID' not in f]

def init(url_rp, url_ar, schemas):
    if is_spid:
        console.log(f"\nSPID Test on: {url_rp}", style = "bold magenta")
    else:
        console.log(f"\nCIE Test on: {url_rp}", style = "bold magenta")
    
    jwt_input=""

    #Analyzing EC
    if url_rp:
        ec_start_time = time.time()
        response = False
        
        if FEDERATION_URL not in url_rp:
            #If not present add a trailing slash and the FEDERATION ENDPOINT
            url_rp = url_rp + ('/' if not url_rp.endswith('/') else '')
            url_ec = url_rp+FEDERATION_URL
        else:
            #If FEDERATION ENDPOINT is present with t trailing slash remove the trailing
            url_rp = url_rp.rstrip('/')
            url_ec = url_rp

        try:
            response = requests.get(url_ec, allow_redirects=True)
        except Exception as e:
            console.print(f"[ERROR] Downloading has failed: {str(e)}", style="bold red")
            test_manager.update_test("1", "Test Result", "[ERROR]")
            test_manager.update_test("1", "Reason/Mitigation", "The URL MUST support .well-known/openid-federation")
            pass
        ec_end_time = time.time()
        ec_time = ec_end_time - ec_start_time
        print(f"Downloading EC time: {ec_time:.2f} seconds")

        if response:
            #Check the method used
            method = response.request.method
            test_manager.append_test(param_manager.increment_value("EC", param_manager.section), "Method GET", "GET" == method, "The response MUST be a GET")

            #Check the status code
            status_code = response.status_code
            test_manager.append_test(param_manager.increment_value("EC", param_manager.section), "Status code", "200" == str(status_code), f"The response MUST return HTTP Status Code 200. Actual is {status_code}")

            #Check headers of HTTP
            content = response.headers.get('Content-Type')
            content = content.split(";", 1)[0]
            if bool(content):
                test_manager.append_test(param_manager.increment_value("EC", param_manager.section), "Content-Type", content == "application/entity-statement+jwt", f"Content-Type MUST be a string valued as 'application/entity-statement+jwt'. The value in the message is {content}")
            else:
                test_manager.append_test(param_manager.increment_value("EC", param_manager.section), "Content-Type", bool(content), "Content-Type MUST be present")

            test_manager.append_test(param_manager.increment_value("EC", param_manager.section), "Return the Entity Configuration Metadata", bool(response), f"The URL at .well.known/openid-federation MUST contain a JWT")

            #Check if return a document
            jwt_input = (response.content).decode('ascii')

            validator = ECValidator()
            validator.validate(jwt_input, schemas, "EC")

            trust_marks = (validator.get_decoded_body()).get('trust_marks')

            #Add the section for different trust_marks
            section_TM = param_manager.get_value("EC Payload", param_manager.section)

            if trust_marks:
                for i, trust_mark_obj in enumerate(trust_marks, 1):
                    param_manager.add_value(f"TM{i}", section_TM + f".{i}", param_manager.section)
                    
                    #Print the main line for Trust Mark #{i}
                    test_manager.append_test(section_TM, f"JWT Trust Mark: #{i}", "[PASSED]", "")

                    trust_mark_jwt = trust_mark_obj.get('trust_mark')

                    validator = TMValidator(i)
                    validator.validate(trust_mark_jwt, schemas, f"TM{i}")
            else:
                test_manager.append_test(section_TM, f"JWT Trust Mark", "[FAILED]", "The Trust Mark MUST be present.")
            
            if is_spid:
                signed_jwks_uri = (validator.get_decoded_body())['metadata']['openid_relying_party'].get('signed_jwks_uri')
                if signed_jwks_uri:
                    try:
                        response = requests.get(signed_jwks_uri, allow_redirects=True)
                    except Exception as e:
                        console.print(f"[ERROR] Downloading has failed: {str(e)}", style="bold red")
                        pass
                
                    if response:
                        jose_input = (response.content).decode('ascii')
                        #decoded_body = jwt.decode(jose_input.replace('\n',''), options={"verify_signature": False})

                        validator = JWKSValidator()
                        validator.validate(jose_input, schemas, "JWKS")

    else:
        test_manager.update_test("1", "Test Result", "[SKIPPED]")
        test_manager.update_test("1", "Reason/Mitigation", "URL not provided")

    #Analyzing AR
    if url_ar:
        ar_start_time = time.time()
        ar_params = False
        
        try:
            response_ar = requests.get(url_ar)
            for resp in response_ar.history:
                url_ar = resp.url
            ar_params = urllib.parse.parse_qs(urlparse(url_ar).query)
        except Exception as e:
            console.print(f"[ERROR] The provided URL is not valid: {str(e)}", style="bold red")
        
        ar_end_time = time.time()
        ar_time = ar_end_time - ar_start_time
        print(f"Downloading AR time: {ar_time:.2f} seconds")

        if ar_params:
            jwt_input = ar_params.get('request')
            
            #Create entry for request JWT and add the result
            param_manager.add_value("ARR", param_manager.get_value("AR", param_manager.section)+".1", param_manager.section)                
            test_manager.append_test(param_manager.increment_value("AR", param_manager.section), "request (JWT)", bool(jwt_input), "The request parameter MUST be present in the HTTP message of Authorization Request.")

            validator = ARValidator(ar_params)
            validator.validate(jwt_input, schemas, "ARR")
    else:
        test_manager.update_test("2", "Reason/Mitigation", "URL not provided")
        test_manager.update_test("2", "Test Result", "[SKIPPED]")
    
    test_manager.update_parent_test(test_manager.simple_output)

    main(test_manager.simple_output, VERBOSE, url_rp)

if __name__ == "__main__":
    #Initialize classes
    param_manager = ParamManager()
    test_manager = TestManager()
    
    #Include the parser
    parser = argparse.ArgumentParser(description="Tool for processing URLs given the URL to the Relying Party Metadata (url_rp) and the Authorization Request")

    #Admitted arguments
    parser.add_argument('--ec', type=str, help='Specify the URL to get RP Metadata.\nExample: https://example.com/relying-party/')
    parser.add_argument('--ar', type=str, help='Specify the Authorization Request URL.\nExample: https://example.com/client_id=hsajkd&')
    parser.add_argument('-f', '--filename', type=str, help='Specify a file including both RP URLs and AR URLs, where RP stays on the line before its AR.')
    parser.add_argument('--verbose', action='store_true', help='Specify for a verbose output.')
    parser.add_argument('--spid', action='store_true', help='Specify if the test is done for SPID on default will be for CIE')

    #Parse the arguments
    args = parser.parse_args()

    #Extract arguments
    url_rp = args.ec
    url_ar = args.ar
    is_spid = args.spid
    inputFile = args.filename
    if args.verbose:
        VERBOSE = True
    
    #Load schemas
    file_names = select_files(is_spid)

    schemas = {}
    for file_name in file_names:
        try:
            with open(os.path.join(INPUT_SCHEMA, file_name), 'r') as schema_file:
                schema_key = file_name.split('.')[0].replace("_SPID", "") + '_schema'
                schemas[schema_key] = json.load(schema_file)
        except FileNotFoundError:
            console.print(f"[ERROR] {file_name} not found in {INPUT_SCHEMA}.", style="bold red")
        except json.JSONDecodeError:
            console.print(f"[ERROR] {file_name} is not a valid JSON file.", style="bold red")
        except Exception as e:
            console.print(f"[ERROR] An unexpected error occurred: {str(e)}", style="bold red")

    #Enter required missing arguments
    if inputFile is None:
        if url_rp is None:
            url_rp = input("Enter the URL of the Relying Party: ")
        if url_ar is None:
            url_ar = input("Enter the URL to obtain the Authorization Request: ")
        init(url_rp, url_ar, schemas)
    else:
        try:
            with open (inputFile, 'r') as input_file:
                index = 1
                for line in input_file.readlines():
                    line = line.strip()
                    #Skip empty lines
                    if not line or line == '\n':
                        continue
                    #Even line
                    if index % 2 == 0:
                        url_ar = line.strip()
                        #When both the URLs analyze them
                        init(url_rp,url_ar,schemas)
                        #Continue
                        reset_all()
                    #Odd line
                    else:
                        url_rp = line.strip()
                    index = index + 1
        except FileNotFoundError:
            console.print(f"[ERROR] {inputFile} is not found.", style="bold red")
        except Exception as e:
            console.print(f"[ERROR] An unexpected error occurred: {str(e)}", style="bold red")
