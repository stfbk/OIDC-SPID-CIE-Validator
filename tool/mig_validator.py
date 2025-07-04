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
                    self.update_test(parent_id, "Reason/Mitigation", f"Some of the subtests failed. See subsequent, e.g., {test['ID']}")
                #If parent has no result, check if all subsections are passed
                elif parent["Test Result"] in ["FAILED", "[FAILED]", "PASSED", ""]:
                    siblings = [t for t in self.simple_output if t["ID"].startswith(parent_id + '.')]
                    #If all siblings have passed, set the parent as PASSED
                    if all(s["Test Result"] in ["PASSED", "[PASSED]"] for s in siblings):
                        self.update_test(parent_id, "Test Result", "[PASSED]")
                        self.update_test(parent_id, "Reason/Mitigation", "All subtests passed.")

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
            "iss": ""
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
            console.print(f"[WARNING] Key '{key}' does not exist in the dictionary. Cannot update.", style="bold red")
    
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
                console.print(f"[WARNING] Invalid version format for '{key}' in {param_dict}.", style="bold red")
        else:
            console.print(f"[WARNING] Key '{key}' does not exist in the dictionary. Cannot update.", style="bold red")

    #Method to add a new key-value pair to a specified dictionary
    @staticmethod
    def add_value(key:str, value: Any, param_dict: Dict[str, Any]):
        param_dict[key] = value
    
    #Method to convert the keys as pem in binary utf-8
    def convert_keys(keys: List[Dict[str, Any]]):
        if keys:
            for k in keys:
                #Create key
                key = JsonWebKey.import_key(k)
                binary_key = key.as_pem(is_private=False).decode('utf-8')
                k['n'] = binary_key
        return keys

    #Method to save the kid value
    def save_kid(self, keys: List[Dict[str, Any]]):
        converted_keys = ParamManager.convert_keys(keys)
        #Save kid and key
        for ck in converted_keys:
            if ck.get('use')=="sig" or not bool(ck.get('use')):
                if ck.get('kid') not in self.saved_param and bool(ck.get('kid')):
                    self.add_value(ck.get('kid'), ck.get('n'), self.saved_param)

#Class that provides methods for validating various data formats, .g., schema, signature
class Validator(ABC):
    test_manager = TestManager()
    param_manager = ParamManager()
    schemas = None

    def __init__(self):
        pass

    @classmethod
    def reset_managers(cls):
        cls.test_manager = TestManager()
        cls.param_manager = ParamManager()

    @abstractmethod
    def validate(self, jwt_input: str, input_data: Dict[str, Any], msg: str) -> None:
        if jwt_input:
            if isinstance(jwt_input, list):
                jwt_input = jwt_input[0]
            self.decoded_body, self.alg, self.kid = Validator.validate_and_decode_jwt(input_data, jwt_input, msg)
            self.additional_checks(self.decoded_body, self.kid)
            result, response = Validator.from_saved_kid_validate_signature(jwt_input, self.alg, self.kid)
            Validator.test_manager.append_test(Validator.param_manager.get_value(msg, Validator.param_manager.section), "Signature", result, response)

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
    def validate_schema (part:dict, schema:dict)-> List[Dict]:
        """
        Validates a JSON Web Token component against a schema.
        
        Args:
            part: Dictionary containing the JWT component to validate
            schema: Dictionary containing the validation schema
        
        Returns:
            List of dictionaries containing error information
            Bool if any error printed on console
        """
        try:
            validator = Draft202012Validator(schema)
            return sorted(validator.iter_errors(part), key=lambda e: e.path)

        except Exception as e:
            console.print(f"[WARNING] Unexpected error during schema validation: {str(e)}", style="bold red")
            return False

    @staticmethod
    def report_errors(errors, which_schema:str, msg:str):
        """
        Reports validation errors to the test manager system, logging each error with its location and details.
        
        Args:
            errors: List of error dictionaries containing validation results
            which_schema: String indicating which part ("Header", "Payload")
            msg: Message identifier for parameter management (EC, AR or TM{i})
        """
        # Construct the main identifier
        msg = msg + " " + which_schema
        main_id = ".".join(Validator.param_manager.get_value(msg, Validator.param_manager.section).split(".")[:-1])
        
        if errors:
            # Handle validation errors
            Validator.test_manager.append_test(main_id, "JWT "+ which_schema, "[FAILED]", "")

            for i, error in enumerate(errors, 1):
                # Format the error path (handle nested paths)
                path_error = ".".join(str(p) for p in error.path) or ""

                if path_error:
                    Validator.test_manager.append_test(Validator.param_manager.increment_value(msg, Validator.param_manager.section), "$."+path_error, "FAILED", error.message)
                else:
                    keyitem, message = Validator.test_manager.change_error_message(error.message)
                    Validator.test_manager.append_test(Validator.param_manager.increment_value(msg, Validator.param_manager.section), "$."+keyitem , "FAILED", message)
            
        else:
            #No error, for sure the main ID, e.g, Header, Payload, Signature
            Validator.test_manager.append_test(main_id, "JWT " + which_schema, "[PASSED]", "")

    @staticmethod
    def from_saved_kid_validate_signature (jwt_input: Dict[str, Any], alg: int, kid: str)->str:
        kid = Validator.param_manager.get_value(kid, Validator.param_manager.saved_param)

        if not url_rp:
            return "[MISSING]", "The PUBLIC_KEY is missing, missing URL. Cannot perform the check"
        
        return Validator.validate_signature(jwt_input, alg, kid)
    
    @staticmethod
    def validate_signature(jwt_input: Dict[str, Any], alg: int, kid: str)->str:

        if not kid:
            return "[MISSING]", "The PUBLIC_KEY is missing, missing kid. Cannot perform the check"
        try:
            # Decode and validate the JWT
            decoded_payload = jwt.decode(
                jwt_input.strip(),
                kid,
                algorithms=[alg],
                options={"verify_aud": False, "verify_exp": False},
                leeway=300 #5minutes
            )
            return "[PASSED]", "The signature for JWT is valid and correct."
        except InvalidTokenError as e:
            return "[FAILED]", f"Signature for JWT failed: {str(e)}"
        except Exception as e:
            return "[WARNING]", f"An unexpected error occurred: {str(e)}"

    @classmethod
    def decode_jwt(cls, jwt_input: str):
        try:     
            #Decode header and body of the JWT without verifying the signature
            decoded_body = jwt.decode(jwt_input.replace('\n',''), options={"verify_signature": False})
            decoded_header = jwt.get_unverified_header(jwt_input.replace('\n',''))
        except jwt.exceptions.DecodeError as e:
            console.print(f"[WARNING] JWT decoding error: {e}", style="bold red")
            return False, False

        return decoded_body, decoded_header

    @classmethod
    def validate_and_decode_jwt(cls, schemas:dict, jwt_input:str, msg:str):
        #Add Header and Payload
        cls.param_manager.add_value(msg+" Header", cls.param_manager.increment_value(msg, cls.param_manager.section)+".1", cls.param_manager.section)
        cls.param_manager.add_value(msg+" Payload", cls.param_manager.increment_value(msg, cls.param_manager.section)+".1", cls.param_manager.section)
        
        #Check if it is REALLY a JWT, if not raise an Error
        cls.test_manager.append_test(cls.param_manager.increment_value(msg, cls.param_manager.section), "Valid JWT", cls.is_jwt(jwt_input), f"It MUST be a valid JWT")

        if cls.is_jwt (jwt_input):
            alg = ""
            kid = ""

            #For TM there is the number only on the message but not on the schema
            entity = msg[:-1] if "TM" in msg else msg

            #Access the loaded schemas
            header_schema = schemas.get(entity+'_header_schema')
            body_schema = schemas.get(entity+'_body_schema')

            decoded_body, decoded_header = cls.decode_jwt(jwt_input)

            if decoded_body or decoded_header:
                try:
                    #Save alg and kid for future usage
                    alg = decoded_header.get('alg', "")
                    kid = decoded_header.get('kid', "")

                    if header_schema:
                        errors = cls.validate_schema(decoded_header, header_schema)
                        if not isinstance(errors, bool):
                            cls.report_errors(errors, "Header", msg)
                    else:
                        console.print(f"[WARNING] The {msg} header schema has not been loaded", style="bold red")

                    if body_schema:
                        errors = cls.validate_schema(decoded_body, body_schema)
                        if not isinstance(errors, bool):
                            cls.report_errors(errors, "Payload", msg)
                    else:
                        console.print(f"[WARNING] The {msg} payload schema has not been loaded", style="bold red")

                except jsonschema.exceptions.ValidationError as e:
                    console.print(f"[WARNING] Schema validation error: {e.message}", style="bold red")
                    return False
            
            return decoded_body, alg, kid

        else:
            console.print(f"[WARNING] The downloaded {msg} content does not contain a valid JWT.", style="bold red")

class ECValidator(Validator):
    def __init__(self):
        super().__init__()
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
            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC Payload", Validator.param_manager.section), "$.iss == $.sub", iss==sub, f"Both issuer and subject value in Entity Configuration JWT MUST be present and have the same value\n  iss: {iss}\n  sub: {sub}")
        # save iss
        Validator.param_manager.update_value("iss", iss, Validator.param_manager.saved_param)

        #Second check: $.[iat] < $.[exp]
        iat = decoded_body.get('iat')
        exp = decoded_body.get('exp')
        if iat and exp:
            exp_date = datetime.fromtimestamp(int(exp), timezone.utc)
            iat_date = datetime.fromtimestamp(int(iat), timezone.utc)
            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC Payload", Validator.param_manager.section), "$.iat < $.exp", (iat<exp), f"The issuance date, {str(iat_date)}, MUST be earlier than the expiration date, {str(exp_date)}.")
            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC Payload", Validator.param_manager.section), "current_time < $.exp", (time.time()<exp), f"The expiration date MUST be valid and not passed. The expiration date is: {str(exp_date)}")
        else:
            exp_date = ""

        keys = decoded_body.get('jwks', {}).get('keys', [])
        Validator.param_manager.save_kid(keys)
        
        #Data to be saved:
        # a. exp_date
        Validator.param_manager.update_value("exp_date", exp_date, Validator.param_manager.saved_param)

        if bool(decoded_body.get('metadata',{}).get('openid_relying_party',{})):
            #Third check: $.metadata.openid_relying_party[client_id] == URL_RP
            client_id = decoded_body['metadata']['openid_relying_party'].get('client_id')
            if client_id and iss:
                Validator.test_manager.append_test(Validator.param_manager.increment_value("EC Payload", Validator.param_manager.section), "$.metadata.openid_relying_party[client_id] == issuer", client_id == iss, f"The client_id from Entity Configuration Payload JSON in the path of '$.metadata.openid_relying_party' MUST be an HTTPS URL that uniquely identifies the RP:\n  client_id: {client_id}\n issuer: {iss}")
            
            # b. public_pem
            jwk_keys = decoded_body['metadata']['openid_relying_party'].get('jwks', {}).get('keys', [])
            Validator.param_manager.save_kid(jwk_keys)
            
            # e1. Check it is the same of the one in header
            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC Payload", Validator.param_manager.section), "kid == $.metadata.openid_relying_party.jwks.keys[kid]", kid in Validator.param_manager.saved_param, "The kid in the header MUST be the same of the signing kid in the metadata")

            # c. $.metadata.openid_relying_party[redirect_uris]
            Validator.param_manager.update_value("redirect_uris", decoded_body['metadata']['openid_relying_party'].get('redirect_uris', []), Validator.param_manager.saved_param)

            # d. $.metadata.openid_relying_party[response_type]
            Validator.param_manager.update_value("response_type", decoded_body['metadata']['openid_relying_party'].get('response_types', []), Validator.param_manager.saved_param)

        # f. $.authority_hints
        authority_hints = decoded_body.get('authority_hints', {})
        Validator.param_manager.update_value("authority_hints", authority_hints, Validator.param_manager.saved_param)
        # iss of trustmark
        tm_iss = decoded_body.get('trust_marks')[0].get('iss')
        result = self.validation_authority_hints(authority_hints, iss, tm_iss)
        if isinstance(result, bool):
            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC Payload", Validator.param_manager.section), "Valid Trust Chain", result, "The trust chain from authority_hints has been validated.")
        else:
            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC Payload", Validator.param_manager.section), "Valid Trust Chain from authority_hints", False, result)

    def validation_authority_hints(self, authority_hints, iss, tm_iss)->str:
        last_auth = len(authority_hints)-1
        #For each ES[j] in auth_hints
        for i, e in enumerate(authority_hints):
            response, jwt_input = url_requests(e, True)

            if response:
                decoded_body, decoded_header = Validator.decode_jwt(jwt_input)

                #Verify that the statement contains all the required claims
                # header
                head_errors = Validator.validate_schema(decoded_header, self.schemas.get('EC_header_schema'))
                if head_errors:
                    return f'The header of {e} is incorrect.'
                
                # body
                if not (decoded_body.get('trust_marks') and decoded_body.get('authority_hints')):
                    #check schema of TA
                    body_errors = Validator.validate_schema(decoded_body, self.schemas.get('TA_body_schema'))
                    if body_errors:
                        return f'The body of {e} is incorrect.'
                else:
                    #check schema of EC
                    body_errors = Validator.validate_schema(decoded_body, self.schemas.get('EC_body_schema'))
                    if body_errors:
                        return f'The body of {e} is incorrect.'

                iat = decoded_body.get('iat')
                exp = decoded_body.get('exp')
                if iat and exp:
                    exp_date = datetime.fromtimestamp(int(exp), timezone.utc)
                    iat_date = datetime.fromtimestamp(int(iat), timezone.utc)
                    #Verify that iat has a value in the past.
                    if (iat>time.time()):
                        return f"The issuance date, {str(iat_date)}, MUST be earlier than the actual date, {time.time()}."
                    #Verify that exp has a value that is in the future.
                    if (exp<time.time()):
                        return f"The expiration, {str(exp_date)}, date MUST be valid and not passed, {time.time()}."
                
                #For each j = 0,...,i-1                
                if i != last_auth:
                    #verify that ES[j]["iss"] == ES[j+1]["sub"].
                    sub = decoded_body.get('sub')
                    if iss != sub:
                        return "Trust chain NOT validated, iss != sub in authority_hints."
                    iss = sub
                    #verify that the signature of ES[j] validates with a public key in ES[j+1]["jwks"].
                    if i == 0:
                        old_header = decoded_header
                        old_jwt_input = jwt_input
                    else:
                        validate = ECValidator.internal_validation(decoded_body, old_header, old_jwt_input)
                        if not validate:
                            return validate
                        old_header = decoded_header
                        old_jwt_input = jwt_input

                #For ES[i] (the Trust Anchor's Entity Configuration) check in TM
                if i == last_auth:
                    #verify that the issuer matches the Entity Identifier of the Trust Anchor
                    iss = decoded_body.get('iss')
                    if iss != tm_iss:
                        return "Trust chain NOT validated, the issuer does not match the Entity Identifier of the Trust Anchor."
                    return ECValidator.internal_validation(decoded_body, decoded_header, jwt_input)
                    
                return True

            return f'Cannot contact {e}.'

    def internal_validation(decoded_body, decoded_header, jwt_input):
        #verify that its signature validates with a public key of the Trust Anchor
        converted_keys = ParamManager.convert_keys(decoded_body.get('jwks', {}).get('keys', []))
        # - select the key with corresponding kid
        for ck in converted_keys:
            if decoded_header.get('kid') == ck.get('kid'):
                message, response = Validator.validate_signature(jwt_input, decoded_header.get('alg'), ck.get('n'))
            
        if not message or message != ('[PASSED]'):
                return f"Trust chain NOT validated, the Trust Anchor does not valid its signature. {response}"
            
        return True

class TMValidator(Validator):
    def __init__(self, tm_number):
        self.tm_number = tm_number

    def validate(self, trust_mark_jwt: str, input_data: Dict[str, Any], msg: str) -> None:
        super().validate(trust_mark_jwt, input_data, msg)

    def additional_checks(self, tm_body: list, kid:str):
            #Call for iss entity configuration to retrieve signature
            iss = tm_body.get('iss')
            response, jwt_input = url_requests(iss, True)

            #Decode JWT and save key
            if response:
                decoded_body, decoded_header = super().decode_jwt(jwt_input)

                keys = decoded_body.get('jwks', {}).get('keys', [])
                Validator.param_manager.save_kid(keys)

            #First check: $.[sub]==url_rp
            sub = tm_body.get('sub')
            Validator.test_manager.append_test(Validator.param_manager.increment_value(f"TM{self.tm_number} Payload", Validator.param_manager.section), "$.sub == URL_RP", sub==url_rp, f"The subject in the Trust Mark MUST be present and have the same value of URL Relying Party\n  sub: {sub}\n  url_rp: {url_rp}")

            #Second check: check kid parameter
            Validator.test_manager.append_test(Validator.param_manager.increment_value(f"TM{self.tm_number} Payload", Validator.param_manager.section), "$.kid in $.metadata.openid_relying_party.jwks.keys[kid]", kid in Validator.param_manager.saved_param, f"The kid value in the header of the jwt of the Trust Mark MUST be the same of the kid value in the jwks of the Metadata RP.")

            #Third check: check iss is in auth_hints
            iss = tm_body.get('iss')
            authority_hints = Validator.param_manager.get_value("authority_hints", Validator.param_manager.saved_param)
            Validator.test_manager.append_test(Validator.param_manager.increment_value(f"TM{self.tm_number} Payload", Validator.param_manager.section), "$.iss in $.authority_hints", iss in [item.rstrip('/') for item in authority_hints], f"The iss of the Trust Mark MUST be a superior entity, i.e., authority_hints in the Metadata\n iss: {iss}\n authority_hints: {authority_hints}")

            #Fourth check: expiration date must be valid
            exp = tm_body.get('exp', 0)
            iat = tm_body.get('iat', 0)
            if exp:
                exp_date = datetime.fromtimestamp(int(exp), timezone.utc)
                Validator.test_manager.append_test(Validator.param_manager.increment_value(f"TM{self.tm_number} Payload", Validator.param_manager.section), "current_time < $.exp", (time.time()<exp), f"The expiration date MUST be valid and not passed\n  expiration: {str(exp_date)}")
                Validator.test_manager.append_test(Validator.param_manager.increment_value(f"TM{self.tm_number} Payload", Validator.param_manager.section), "$.iat < $.exp", (iat<exp), f"The expiration date MUST be valid and not passed\n  expiration: {str(exp_date)}")

class ARValidator(Validator):
    def __init__(self, ar_params):
        self.ar_params = ar_params

    def validate(self, jwt_input: str, input_data: Dict[str, Any], msg: str) -> None:
        super().validate(jwt_input, input_data, msg)

    def additional_checks(self, decoded_body: str, kid:str):
        #First Check: $.[client_id] == iss
        client_id_body = decoded_body.get('client_id')
        iss = Validator.param_manager.get_value('iss', Validator.param_manager.saved_param)
        Validator.test_manager.append_test(Validator.param_manager.increment_value("ARR Payload", Validator.param_manager.section), "$.client_id == iss of RP's EntityConfiguration", (client_id_body==iss), f"The client_id in the payload of the JWT Authorization Request MUST be present AND equal to the URL of the Relying Party\n  $.client_id: {client_id_body}\n  iss: {iss}")

        #Second check: # $.[redirect_uri] is in body of the EC $.metadata.openid_relying_party[redirect_uris]
        redirect_uri = decoded_body.get('redirect_uri')
        redirect_uris = Validator.param_manager.get_value("redirect_uris", Validator.param_manager.saved_param)
        Validator.test_manager.append_test(Validator.param_manager.increment_value("ARR Payload", Validator.param_manager.section), "$.redirect_uri in $.metadata.openid_relying_party[redirect_uris]", redirect_uri is not None and redirect_uri in redirect_uris, f"The redirect_uri in the payload of the JWT Authorization Request payload MUST be present AND in the list of the redirect_uris provided in the Entity Configuration payload\n  $.redirect_uri: {redirect_uri}\n  $.metadata.openid_relying_party.redirect_uris: {redirect_uris}")

        #2b check: # $.[response_type] is in body of the EC $.metadata.openid_relying_party[response_type]
        response_type = decoded_body.get('response_type')
        response_types = Validator.param_manager.get_value("response_type", Validator.param_manager.saved_param)
        Validator.test_manager.append_test(Validator.param_manager.increment_value("ARR Payload", Validator.param_manager.section), "$.response_type in $.metadata.openid_relying_party[response_type]", response_type is not None and response_type in response_types, f"The response_type in the payload of the JWT Authorization Request payload MUST be present AND in the list of the response_types provided in the Entity Configuration payload\n  $.response_type: {response_type}\n  $.metadata.openid_relying_party.response_types: {response_types}")

        #Third Check: check kid parameter
        Validator.test_manager.append_test(Validator.param_manager.increment_value("ARR Payload", Validator.param_manager.section), "$.kid in $.metadata.openid_relying_party.jwks.keys[kid]", kid in Validator.param_manager.saved_param, f"The kid value in the header of the jwt request MUST be the same of the kid value in the jwks of the Metadata RP")

        #Fourth check: expiration date must be valid
        exp = decoded_body.get('exp', 0) 
        if exp:
            exp_date = datetime.fromtimestamp(int(exp), timezone.utc)
            Validator.test_manager.append_test(Validator.param_manager.increment_value("ARR Payload", Validator.param_manager.section), "current_time < $.exp", (time.time()<exp), f"The expiration date MUST be valid and not passed. The expiration date is: {str(exp_date)}")

        #Fifth Check: check presence and value of parameter in HTTP Message
        # a. client_id
        client_id_http = self.ar_params.get('client_id')
        #Only SPID check for the presence
        if SPID:
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "client_id", bool(self.ar_params.get('client_id')), "The client_id parameter MUST be present in the HTTP message of Authorization Request.")
        #If exist check the value
        if bool(self.ar_params.get('client_id')) and isinstance(client_id_http, list):
            client_id_http = client_id_http[0]
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "client_id == $.client_id", (client_id_http==client_id_body), f"Both the client_id in the HTTP_message and in the Payload of the JWT request MUST have the same value\n  client_id: {client_id_http}\n  $.client_id: {client_id_body}")
            #client_id is an HTTPS URL
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "client_id is an HTTPS URL", self.is_https_url(client_id_http), f"The client_id in the HTTP_message MUST be an HTTPS URL\n  client_id: {client_id_http}")

        # a1. client_id == $.iss
        iss_decodedBody=decoded_body.get('iss')
        Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "client_id", client_id_http==iss_decodedBody, f"The client_id in the HTTP message and $.iss parameters in the JWT request MUST be equal.\n  client_id: {client_id_http}\n  $.iss: {iss_decodedBody}")

        # b. response_type
        response_type_http = self.ar_params.get('response_type')
        if SPID:
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "response_type", bool(self.ar_params.get('response_type')), f"The response_type parameter MUST be present in the HTTP message of Authorization Request.")
        if bool(self.ar_params.get('response_type')) and isinstance(response_type_http, list):
            response_type_http = response_type_http[0]
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "'code' in response_type", 'code' in response_type_http, f"The value of response_type in the HTTP_message MUST be 'code'\n  response_type: {response_type_http}")
    
        # c. scope
        scope = self.ar_params.get('scope')
        if bool(self.ar_params.get('scope')) and isinstance(scope, list):
            scope = scope[0]
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "scope", 'openid' in scope, f"The scope parameter MUST contain 'openid'\n  scope: {scope}")
            Validator.test_manager.append_test(Validator.param_manager.increment_value("ARR", Validator.param_manager.section), "scope", scope==decoded_body.get('scope'), f"The scope parameter in the HTTP message and JWT Request of Authorization Request MUST be present and have the same value")
        else:
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "scope", bool(self.ar_params.get('scope')), f"The scope parameter MUST be present in the HTTP message of Authorization Request.")

        # d. code_challenge
        if bool(self.ar_params.get('code_challenge')):
            code_challenge=self.ar_params['code_challenge']
            codeChallenge_decoded=decoded_body.get('code_challenge')
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "code_challenge==$.code_challenge", codeChallenge_decoded in code_challenge, f"The code_challenge in the HTTP message and JWT Request of Authorization Request MUST be present and have the same value.\n  code_challenge: {code_challenge}\n  $.code_challenge: {codeChallenge_decoded}")
        else:
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "code_challenge", "FAILED", f"The code_challenge parameter MUST be present in the HTTP message of Authorization Request.")

        # e. code_challenge_method
        if bool(self.ar_params.get('code_challenge_method')):
            code_challenge_method=self.ar_params['code_challenge_method']
            codeChallengeMethod_decoded=decoded_body.get('code_challenge_method')
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "code_challenge_method==$.code_challenge_method", codeChallengeMethod_decoded in code_challenge_method, f"The code_challenge_method in the HTTP message and JWT Request of Authorization Request MUST be present and have the same value.\n  code_challenge_method: {code_challenge_method}\n  $.code_challenge_method: {codeChallengeMethod_decoded}")
        else:
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "code_challenge_method", bool(self.ar_params.get('code_challenge_method')), f"The code_challenge_method parameter MUST be present in the HTTP message of Authorization Request.")

        ARValidator.op_comparison(self, decoded_body)
   
    def op_comparison(self, decoded_body: str):
        ec = False
        #Check aud by calling its EC.
        aud = decoded_body.get('aud')
        list_aud = [aud] if isinstance(aud, str) else aud

        for el_aud in list_aud:
            response, jwt_input = url_requests(el_aud, True)
            #If there is no response there is a warning on that url but no wrong message
            if response:
                ec = True
                new_body, decoded_header = super().decode_jwt(jwt_input)

                #Check iss
                iss = new_body.get('iss')
                Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "$.aud == $.metadata.iss", (iss==el_aud), f"Both the aud in the Payload of the JWT request and the iss in its Entity Configuration MUST have the same value\n  $.metadata.iss: {iss}\n  $.aud: {aud}")
                
                #Check acr_values
                acr_values = decoded_body.get('acr_values')
                acr_values_supported = new_body.get('metadata').get('openid_provider').get('acr_values_supported')
                Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "$.acr_values in $.metadata.openid_provider.acr_values_supported", (acr_values in acr_values_supported), f"The acr_values in the Payload of the JWT request MUST be contained in the acr_values_supported in the OPs Entity Configuration\n:  $.metadata.openid_provider.acr_values_supported: {acr_values_supported}\n  $.acr_values: {acr_values}")

                #Check scope
                scope = decoded_body.get('scope')
                scopes_supported = new_body.get('metadata').get('openid_provider').get('scopes_supported')
                print("QUI: ",scope, scopes_supported)
                print(scope in scopes_supported)
                Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "$.scope in $.metadata.openid_provider.scopes_supported", (scope in scopes_supported), f"The scope in the Payload of the JWT request MUST be contained in the scopes_supported in the OPs Entity Configuration\n:  $.metadata.openid_provider.scopes_supported: {scopes_supported}\n  $.scope: {scope}")
    
        #If there is no response something is wrong
        if not ec:
            Validator.test_manager.append_test("AR", "Reason/Mitigation", "The 'aud' in JWT request MUST support .well-known/openid-federation")
        
        return

class JWKSValidator(Validator):
    def __init__(self):
        pass
    
    def validate(self, jwks_uri_jwt: str, input_data: Dict[str, Any], msg: str) -> None:
        super().validate(jwks_uri_jwt, input_data, msg)

    def additional_checks(self, decoded_body: str, kid: str):
        # No additional checks needed for JWKSValidator
        pass

#Reset all for restart
def reset_all():
    global url_rp
    global url_ar
    
    url_ar = ""
    url_rp = ""
    Validator.reset_managers()

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

#Method to load schemas
def load_schemas(is_spid):
    file_names = select_files(is_spid)

    schemas = {}
    for file_name in file_names:
        try:
            with open(os.path.join(INPUT_SCHEMA, file_name), 'r') as schema_file:
                schema_key = file_name.split('.')[0].replace("_SPID", "") + '_schema'
                schemas[schema_key] = json.load(schema_file)
        except FileNotFoundError:
            console.print(f"[WARNING] {file_name} not found in {INPUT_SCHEMA}.", style="bold red")
        except json.JSONDecodeError:
            console.print(f"[WARNING] {file_name} is not a valid JSON file.", style="bold red")
        except Exception as e:
            console.print(f"[WARNING] An unexpected error occurred: {str(e)}", style="bold red")
    return schemas

#Method to get responses. Return response, boolean, and param, the decoded body
def url_requests(url:str, fed:bool):
    param = False

    if fed:
        if FEDERATION_URL not in url_rp:
            #If not present add the trailing slash then add the FEDERATION ENDPOINT
            old_url = url + ('/' if not url.endswith('/') else '')
            url = old_url+FEDERATION_URL
        else:
            #If FEDERATION ENDPOINT is present with the trailing slash remove the trailing
            old_url = url.rstrip('/')
            url = old_url
    
    try:
        response = requests.get(url, allow_redirects=True)
    except Exception as e:
        console.print(f"[WARNING] The provided URL is not valid: {str(e)}", style="bold red")
        return False, False

    if fed:
        param = response.content.decode('ascii')
    else:
        for resp in response.history:
            url = resp.url
        param = urllib.parse.parse_qs(urlparse(url).query)
    
    return response, param

#Init
def init(url_rp, url_ar):
    #Load schemas
    schemas = load_schemas(is_spid)
    Validator.schemas = schemas

    global SPID
    if is_spid:
        console.log(f"\nSPID Test on: {url_rp}", style = "bold magenta")
        SPID = True
    else:
        console.log(f"\nCIE Test on: {url_rp}", style = "bold magenta")
    
    jwt_input=""
    
    #Analyzing EC
    if url_rp:
        ec_start_time = time.time()
        response, jwt_input = url_requests(url_rp, True)
        ec_end_time = time.time()
        ec_time = ec_end_time - ec_start_time
        print(f"Downloading EC time: {ec_time:.2f} seconds")

        if response:
            #Check the method used
            method = response.request.method
            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC", Validator.param_manager.section), "Method GET", "GET" == method, "The response MUST be a GET")

            #Check the status code
            status_code = response.status_code
            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC", Validator.param_manager.section), "Status code", "200" == str(status_code), f"The response MUST return HTTP Status Code 200. Actual is {status_code}")

            #Check headers of HTTP
            content = response.headers.get('Content-Type')
            content = content.split(";", 1)[0]
            if bool(content):
                Validator.test_manager.append_test(Validator.param_manager.increment_value("EC", Validator.param_manager.section), "Content-Type", content == "application/entity-statement+jwt", f"Content-Type MUST be a string valued as 'application/entity-statement+jwt'. The value in the message is {content}")
            else:
                Validator.test_manager.append_test(Validator.param_manager.increment_value("EC", Validator.param_manager.section), "Content-Type", bool(content), "Content-Type MUST be present")

            Validator.test_manager.append_test(Validator.param_manager.increment_value("EC", Validator.param_manager.section), "Return the Entity Configuration Metadata", bool(response), f"The URL at .well.known/openid-federation MUST contain a JWT")

            validator = ECValidator()
            validator.validate(jwt_input, schemas, "EC")

            trust_marks = (validator.get_decoded_body()).get('trust_marks')

            #Add the section for different trust_marks
            section_TM = Validator.param_manager.get_value("EC Payload", Validator.param_manager.section)

            if trust_marks:
                for i, trust_mark_obj in enumerate(trust_marks, 1):
                    Validator.param_manager.add_value(f"TM{i}", section_TM + f".{i}", Validator.param_manager.section)
                    
                    #Print the main line for Trust Mark #{i}
                    Validator.test_manager.append_test(section_TM, f"JWT Trust Mark: #{i}", "[PASSED]", "")

                    trust_mark_jwt = trust_mark_obj.get('trust_mark')

                    validator = TMValidator(i)
                    validator.validate(trust_mark_jwt, schemas, f"TM{i}")
            else:
                Validator.test_manager.append_test(section_TM, f"JWT Trust Mark", "[FAILED]", "The Trust Mark MUST be present.")
            
            if is_spid:
                signed_jwks_uri = (validator.get_decoded_body())['metadata']['openid_relying_party'].get('signed_jwks_uri')
                if signed_jwks_uri:
                    try:
                        response = requests.get(signed_jwks_uri, allow_redirects=True)
                    except Exception as e:
                        console.print(f"[WARNING] Downloading has failed: {str(e)}", style="bold red")
                        pass
                
                    if response:
                        jose_input = (response.content).decode('ascii')
                        #decoded_body = jwt.decode(jose_input.replace('\n',''), options={"verify_signature": False})

                        validator = JWKSValidator()
                        validator.validate(jose_input, schemas, "JWKS")
        else:
            Validator.test_manager.update_test("1", "Test Result", "[WARNING]")
            Validator.test_manager.update_test("1", "Reason/Mitigation", "The URL MUST support .well-known/openid-federation")
    else:
        Validator.test_manager.update_test("1", "Test Result", "[SKIPPED]")
        Validator.test_manager.update_test("1", "Reason/Mitigation", "URL not provided")

    #Analyzing AR
    if url_ar:
        ar_start_time = time.time()
        response_ar, ar_params = url_requests(url_ar, False)
        ar_end_time = time.time()
        ar_time = ar_end_time - ar_start_time
        print(f"Downloading AR time: {ar_time:.2f} seconds")

        if ar_params:
            jwt_input = ar_params.get('request')
            
            #Create entry for request JWT and add the result
            Validator.param_manager.add_value("ARR", Validator.param_manager.get_value("AR", Validator.param_manager.section)+".1", Validator.param_manager.section)                
            Validator.test_manager.append_test(Validator.param_manager.increment_value("AR", Validator.param_manager.section), "request (JWT)", bool(jwt_input), "The request parameter MUST be present in the HTTP message of Authorization Request.")

            validator = ARValidator(ar_params)
            validator.validate(jwt_input, schemas, "ARR")
    else:
        Validator.test_manager.update_test("2", "Reason/Mitigation", "URL not provided")
        Validator.test_manager.update_test("2", "Test Result", "[SKIPPED]")
    
    Validator.test_manager.update_parent_test(Validator.test_manager.simple_output)

    main(Validator.test_manager.simple_output, VERBOSE, url_rp)

if __name__ == "__main__":
    #Include the parser
    parser = argparse.ArgumentParser(description="Tool for processing URLs given the URL to the Relying Party Metadata (url_rp) and the Authorization Request")

    #Admitted arguments
    parser.add_argument('--eid', type=str, help='Specify the URL to get RP Metadata.\nExample: https://example.com/relying-party/')
    parser.add_argument('--ar', type=str, help='Specify the Authorization Request URL.\nExample: https://example.com/client_id=hsajkd&')
    parser.add_argument('-f', '--filename', type=str, help='Specify a file including both RP URLs and AR URLs, where RP stays on the line before its AR.')
    parser.add_argument('--verbose', action='store_true', help='Specify for a verbose output.')
    parser.add_argument('--spid', action='store_true', help='Specify if the test is done for SPID on default will be for CIE')

    #Parse the arguments
    args = parser.parse_args()

    #Extract arguments
    url_rp = args.eid
    url_ar = args.ar
    is_spid = args.spid
    inputFile = args.filename
    if args.verbose:
        VERBOSE = True

    #Enter required missing arguments
    if inputFile is None:
        if url_rp is None:
            url_rp = input("Enter the URL of the Relying Party: ")
        if url_ar is None:
            url_ar = input("Enter the URL to obtain the Authorization Request: ")
        init(url_rp, url_ar)
    #If File as input
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
                        init(url_rp,url_ar)
                        #Continue
                        reset_all()
                    #Odd line
                    else:
                        url_rp = line.strip()
                    index = index + 1
        except FileNotFoundError:
            console.print(f"[WARNING] {inputFile} is not found.", style="bold red")
        except Exception as e:
            console.print(f"[WARNING] An unexpected error occurred: {str(e)}", style="bold red")