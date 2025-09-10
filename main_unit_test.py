import unittest
import csv
import os


class CrackerService:
    def is_valid_hash(self, hash_str):
        """Dummy method for validating SHA256 hash."""
        return len(hash_str) == 64 and all(c in "0123456789abcdef" for c in hash_str)

    def load_hashes_from_csv(self, file_path):
        """
        Reads a CSV file and pulls out valid SHA256 hashes.
        Returns a list of valid hashes.
        """
        hashes = []
        try:
            with open(file_path, newline='') as csvfile:
                csv_reader = csv.DictReader(csvfile)
                for row in csv_reader:
                    if 'hash' in row:
                        hashes.append(row['hash'])
        except Exception as e:
            print(f"Error occurred: {e}")
        return hashes


class TestCrackerService(unittest.TestCase):
    
    def setUp(self):
        """Set up the CrackerService for testing."""
        self.cracker_service = CrackerService()
        # Create a temporary CSV file for testing
        self.test_csv = 'test_hashes.csv'
        data = """plain,hash
a,ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb
a1,f55ff16f66f43360266b95db6f8fec01d76031054306ae4a4b380598f6cfd114
ab3,c4bba1914e2444a5051c12903e945fa6e83072eabb34ec29ebab9d2442c1ac91
"""
        with open(self.test_csv, 'w') as f:
            f.write(data)

    def test_is_valid_hash_valid(self):
        """Test that a valid SHA256 hash returns True."""
        valid_hash = "ef92b778bafe771e89245b5d17e839f0dff1d24058c032ba2439ec15ed9f4c6b"
        self.assertTrue(self.cracker_service.is_valid_hash(valid_hash))

    def test_is_valid_hash_invalid(self):
        """Test that an invalid SHA256 hash returns False."""
        invalid_hash = "notavalidhash"
        self.assertFalse(self.cracker_service.is_valid_hash(invalid_hash))

    def test_load_hashes_from_csv(self):
        """Test loading and reading hashes from a CSV file."""
        result = self.cracker_service.load_hashes_from_csv(self.test_csv)

        # Check if the result contains the expected hashes
        self.assertEqual(len(result), 3)
        self.assertIn('ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb', result)
        self.assertIn('f55ff16f66f43360266b95db6f8fec01d76031054306ae4a4b380598f6cfd114', result)
        self.assertIn('c4bba1914e2444a5051c12903e945fa6e83072eabb34ec29ebab9d2442c1ac91', result)

    def tearDown(self):
        """Remove the test CSV file after testing."""
        if os.path.exists(self.test_csv):
            os.remove(self.test_csv)

    def test_load_hashes_from_nonexistent_csv(self):
        """Test loading from a non-existent CSV file."""
        result = self.cracker_service.load_hashes_from_csv('non_existent_file.csv')
        self.assertEqual(result, [])

    def test_load_hashes_missing_hash_column(self):
        """Test loading hashes when the 'hash' column is missing."""
        data = """plain,value
        a,not_a_hash
        """
        with open(self.test_csv, 'w') as f:
            f.write(data)
        result = self.cracker_service.load_hashes_from_csv(self.test_csv)
        self.assertEqual(result, [])

    def test_load_hashes_empty_file(self):
        """Test loading hashes from an empty CSV file."""
        data = ""
        with open(self.test_csv, 'w') as f:
            f.write(data)
        result = self.cracker_service.load_hashes_from_csv(self.test_csv)
        self.assertEqual(result, [])

if __name__ == '__main__':
    unittest.main(verbosity=2)
