import unittest
from tool.mig_validator import load_schemas, select_files, INPUT_SCHEMA

class TestSchemaLoader(unittest.TestCase):
    def setUp(self):
        self.is_spid = True  # Or True for SPID schemas, depending on what you want to test
        self.not_spid = False

        self.is_spid_schema = ['ARR_header_schema', 'ARR_body_schema', 'EC_header_schema', 'EC_body_schema', 'JWKS_body_schema', 'TM_body_schema', 'TM_header_schema']
        self.is_spid_files = ['ARR_header.json', 'ARR_body_SPID.json', 'EC_header.json', 'EC_body_SPID.json', 'JWKS_body_SPID.json', 'TM_header.json', 'TM_body.json']
        
        self.not_spid_schema = ['ARR_header_schema', 'ARR_body_schema', 'EC_header_schema', 'EC_body_schema', 'TM_body_schema', 'TM_header_schema']
        self.not_spid_files = ['ARR_header.json', 'ARR_body.json', 'EC_header.json', 'EC_body.json', 'TM_header.json', 'TM_body.json']

    def test_spid_select_load_schemas(self):
        file_names = select_files(self.is_spid)
        self.assertIsInstance(file_names, list)
        self.assertGreater(len(file_names), 0)
        self.assertCountEqual(file_names, self.is_spid_files)

        schemas = load_schemas(self.is_spid)
        self.assertIsInstance(schemas, dict)
        self.assertGreater(len(schemas), 0)
        self.assertCountEqual(schemas, self.is_spid_schema)

    def test_not_spid_select_load_schemas(self):
        file_names = select_files(self.not_spid)
        self.assertIsInstance(file_names, list)
        self.assertGreater(len(file_names), 0)
        self.assertCountEqual(file_names, self.not_spid_files)

        schemas = load_schemas(self.not_spid)
        self.assertIsInstance(schemas, dict)
        self.assertGreater(len(schemas), 0)
        self.assertCountEqual(schemas, self.not_spid_schema)

if __name__ == '__main__':
    unittest.main(verbosity=2)
